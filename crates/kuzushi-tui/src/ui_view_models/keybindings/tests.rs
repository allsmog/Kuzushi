use super::*;
use crate::scene3d::VizPage;
use crate::ui_view_models::WORKBENCH_REPORT_COMMAND;
use crate::{ScanPanelState, ShellView};
use kuzushi_core::V2Config;
use std::path::PathBuf;

fn pending_confirm(kind: crate::app::ConfirmKind) -> crate::app::PendingConfirm {
    crate::app::PendingConfirm {
        kind,
        tool: "recon:nmap".to_string(),
        target: "127.0.0.1".to_string(),
        rationale: None,
        allowlist: None,
        actor: None,
        remembered: false,
    }
}

#[test]
fn descriptor_approval_footer_omits_unsupported_remembered_allow() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.advisory_mut().pending_confirm =
        Some(pending_confirm(crate::app::ConfirmKind::DescriptorEffect));

    let bindings = footer_keybindings(&app);

    assert!(bindings.contains(&bind("y", "allow once")));
    assert!(bindings.contains(&bind("N", "deny for session")));
    assert!(bindings.contains(&bind("Ctrl+C", "quit")));
    assert!(bindings.iter().all(|binding| binding.key != "Y"));
}

#[test]
fn allowlistable_approval_footer_keeps_remembered_allow() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.advisory_mut().pending_confirm =
        Some(pending_confirm(crate::app::ConfirmKind::NetworkEgress));

    let bindings = footer_keybindings(&app);

    assert!(bindings.contains(&bind("Y", "allow for session")));
    assert!(bindings.contains(&bind("N", "deny for session")));
}

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
            prompt.contains(&bind("Esc", "nav mode")),
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
    *app.findings_mut() = vec![workbench_finding()];
    app.router
        .workbench_mut()
        .set_page(Some(crate::app::WorkbenchPage::Review));
    app.router
        .workbench_mut()
        .set_focus(crate::app::WorkbenchPane::Findings);
    let prompt = footer_keybindings(&app);
    assert!(prompt.contains(&bind("Tab", "complete")));
    assert!(prompt.contains(&bind("Shift+Tab", "mode")));
    // Review with findings: the Esc doorway must teach the findings flow the
    // Prompt-mode filter otherwise hides (j/k select, Enter opens Prove).
    assert!(prompt.contains(&bind("Esc", "nav findings · j/k move · Enter prove")));
    assert!(prompt.contains(&bind("scan", "guided plan")));
    assert!(prompt.contains(&bind("run sast:scan {}", "rescan now")));
    assert!(prompt.contains(&bind("Ctrl+C", "exit")));
    assert!(!prompt.contains(&bind("n/N", "page")));
    assert!(!prompt.contains(&bind("1..5", "page")));
    assert!(!prompt.iter().any(|binding| binding.key == "Enter"));

    app.set_input_mode(crate::InputMode::Navigate);
    let navigate = footer_keybindings(&app);
    assert!(navigate.contains(&bind("Esc", "prompt")));
    assert!(navigate.contains(&bind("Shift+Tab", "mode")));
    assert!(navigate.contains(&bind("n/N", "page")));
    assert!(navigate.contains(&bind("1..5", "page")));
    assert!(navigate.contains(&bind("[", "pane back")));
    assert!(navigate.contains(&bind("]", "pane")));
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
        .set_page(Some(crate::app::WorkbenchPage::Map));
    app.router
        .workbench_mut()
        .set_focus(crate::app::WorkbenchPane::Center);
    assert!(footer_keybindings(&app)
        .iter()
        .all(|binding| binding.key != "Tab"));
    assert!(app
        .view_keybindings()
        .iter()
        .all(|binding| binding.hint != "Tab"));

    *app.findings_mut() = vec![workbench_finding()];
    app.router
        .workbench_mut()
        .set_page(Some(crate::app::WorkbenchPage::Review));
    app.router
        .workbench_mut()
        .set_focus(crate::app::WorkbenchPane::Findings);
    assert!(footer_keybindings(&app)
        .iter()
        .any(|binding| binding.key == "Tab"));
    assert!(app
        .view_keybindings()
        .iter()
        .any(|binding| binding.hint == "Tab"));

    app.router
        .workbench_mut()
        .set_focus(crate::app::WorkbenchPane::Details);
    assert!(footer_keybindings(&app)
        .iter()
        .any(|binding| binding.key == "q"));

    app.router
        .workbench_mut()
        .set_page(Some(crate::app::WorkbenchPage::Prove));
    app.router
        .workbench_mut()
        .set_focus(crate::app::WorkbenchPane::Source);
    let prove = footer_keybindings(&app);
    for key in ["v", "x", "c"] {
        assert!(prove.iter().any(|binding| binding.key == key), "{prove:?}");
    }
    assert!(prove.iter().all(|binding| binding.key != "q"), "{prove:?}");
}

#[test]
fn workbench_footer_advertises_the_report_exit_when_findings_exist() {
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

    assert!(bindings.contains(&bind(WORKBENCH_REPORT_COMMAND, "open Report")));
}

#[test]
fn workbench_footer_only_advertises_enter_for_an_actionable_findings_pane() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Workbench);
    app.set_input_mode(crate::InputMode::Navigate);

    app.router
        .workbench_mut()
        .set_page(Some(crate::app::WorkbenchPage::Map));
    app.router
        .workbench_mut()
        .set_focus(crate::app::WorkbenchPane::Center);
    assert!(footer_keybindings(&app)
        .iter()
        .all(|binding| binding.key != "Enter"));

    *app.findings_mut() = vec![workbench_finding()];
    app.router
        .workbench_mut()
        .set_page(Some(crate::app::WorkbenchPage::Review));
    app.router
        .workbench_mut()
        .set_focus(crate::app::WorkbenchPane::Findings);
    assert!(footer_keybindings(&app).contains(&bind("Enter", "review")));

    app.router
        .workbench_mut()
        .set_page(Some(crate::app::WorkbenchPage::Fix));
    assert!(footer_keybindings(&app)
        .iter()
        .all(|binding| binding.key != "Enter"));
}

#[test]
fn prompt_esc_label_teaches_the_findings_flow_only_where_it_exists() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Workbench);
    *app.findings_mut() = vec![workbench_finding()];

    app.router
        .workbench_mut()
        .set_page(Some(crate::app::WorkbenchPage::Scan));
    let scan_page = footer_keybindings(&app);
    assert!(scan_page.contains(&bind("Esc", "nav mode")), "{scan_page:?}");

    app.router
        .workbench_mut()
        .set_page(Some(crate::app::WorkbenchPage::Review));
    *app.findings_mut() = Vec::new();
    let empty_review = footer_keybindings(&app);
    assert!(
        empty_review.contains(&bind("Esc", "nav mode")),
        "{empty_review:?}"
    );

    *app.findings_mut() = vec![workbench_finding()];
    let review = footer_keybindings(&app);
    assert!(
        review.contains(&bind("Esc", "nav findings · j/k move · Enter prove")),
        "{review:?}"
    );
}

fn workbench_finding() -> kuzushi_core::Finding {
    kuzushi_core::Finding::new_semgrep(
        "demo.rule",
        "src/app.rs",
        1,
        Some(1),
        kuzushi_core::Severity::High,
        "demo",
    )
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
    assert!(bindings.contains(&bind("Esc", "nav mode")));
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
        .set_page(Some(crate::app::WorkbenchPage::Review));
    *app.findings_mut() = vec![kuzushi_core::Finding::new_semgrep(
        "demo.rule",
        "src/app.rs",
        1,
        Some(1),
        kuzushi_core::Severity::High,
        "demo",
    )];
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
        .position(|binding| binding.key == "1..5")
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
    assert!(bindings.contains(&bind("1-5", "jump phase")));
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
    assert!(bindings.contains(&bind("1-5", "phase")));
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
fn hot_reloaded_runtime_bindings_drive_footer_chrome() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Workbench);
    let keymap =
        crate::app::RuntimeKeymap::from_config(&[kuzushi_core::config::KeybindingOverrideConfig {
            context: "global".to_string(),
            action: "command_palette".to_string(),
            bindings: vec!["ctrl+p".to_string()],
        }]);
    app.ui_mut().replace_runtime_keymap(keymap).unwrap();

    let bindings = footer_keybindings(&app);

    assert!(bindings.iter().any(|binding| binding.key == "ctrl+p"));
    assert!(!bindings.iter().any(|binding| binding.key == "Ctrl+G"));
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
    let expected = FooterKeybinding {
        key: key.to_string(),
        label: label.to_string(),
    };
    bindings
        .iter()
        .filter(|binding| **binding == expected)
        .count()
}
