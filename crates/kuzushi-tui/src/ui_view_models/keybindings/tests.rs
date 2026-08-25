use super::*;
use crate::scene3d::VizPage;
use crate::ui_view_models::PhaseSurfaceId;
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
    for view in [ShellView::Cost, ShellView::Patch, ShellView::FailureHandoff] {
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
fn auth_view_advertises_a_reachable_back_action() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Auth);

    assert!(footer_keybindings(&app).contains(&bind("Esc", "nav mode")));
    app.set_input_mode(crate::InputMode::Navigate);

    let navigate = footer_keybindings(&app);
    assert!(navigate.contains(&bind("q", "back")));
}

#[test]
fn prompt_footer_names_the_actual_first_escape_effect_for_a_draft() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Workbench);
    app.set_input("verify F-0001");

    let bindings = footer_keybindings(&app);

    assert!(bindings.contains(&bind("Esc", "clear draft · Ctrl+_ restores")));
    assert!(!bindings.iter().any(|binding| {
        binding.key == "Esc" && (binding.label == "nav mode" || binding.label == "back")
    }));
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
        .set_focus(PhaseSurfaceId::ReviewQueue);
    let prompt = footer_keybindings(&app);
    assert!(prompt.contains(&bind("Tab", "complete")));
    assert!(prompt.contains(&bind("Shift+Tab", "next phase")));
    // Review with findings: the Esc doorway must teach the findings flow the
    // Prompt-mode filter otherwise hides (j/k select, Enter opens Prove).
    assert!(prompt.contains(&bind("Esc", "nav findings · j/k move · Enter prove")));
    assert!(prompt.contains(&bind("scan", "Scan phase planner")));
    assert!(prompt.contains(&bind("run sast:scan {}", "rescan now")));
    assert!(prompt.contains(&bind("Ctrl+C", "exit")));
    assert!(!prompt.contains(&bind("n/N", "page")));
    assert!(!prompt.contains(&bind("1..5", "page")));
    assert!(!prompt.iter().any(|binding| binding.key == "Enter"));

    app.set_input_mode(crate::InputMode::Navigate);
    let navigate = footer_keybindings(&app);
    assert!(navigate.contains(&bind("Esc", "prompt")));
    assert!(navigate.contains(&bind("Shift+Tab", "next phase")));
    assert!(navigate.contains(&bind("n/N", "page")));
    assert!(navigate.contains(&bind("1..5", "page")));
    assert!(navigate.contains(&bind("[", "pane back")));
    assert!(navigate.contains(&bind("]", "pane")));
    assert!(!navigate.contains(&bind("scan", "Scan phase planner")));
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
        .set_focus(PhaseSurfaceId::MapAttackSurface);
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
        .set_focus(PhaseSurfaceId::ReviewQueue);
    assert!(footer_keybindings(&app)
        .iter()
        .any(|binding| binding.key == "Tab"));
    assert!(app
        .view_keybindings()
        .iter()
        .any(|binding| binding.hint == "Tab"));

    app.router
        .workbench_mut()
        .set_focus(PhaseSurfaceId::ReviewDetail);
    assert!(footer_keybindings(&app)
        .iter()
        .any(|binding| binding.key == "q"));

    app.router
        .workbench_mut()
        .set_page(Some(crate::app::WorkbenchPage::Prove));
    app.router
        .workbench_mut()
        .set_focus(PhaseSurfaceId::ProveStatus);
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
        .set_focus(PhaseSurfaceId::MapAttackSurface);
    assert!(footer_keybindings(&app)
        .iter()
        .all(|binding| binding.key != "Enter"));

    *app.findings_mut() = vec![workbench_finding()];
    app.router
        .workbench_mut()
        .set_page(Some(crate::app::WorkbenchPage::Review));
    app.router
        .workbench_mut()
        .set_focus(PhaseSurfaceId::ReviewQueue);
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
    assert!(
        scan_page.contains(&bind("Esc", "nav mode")),
        "{scan_page:?}"
    );

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
    assert!(bindings.contains(&bind("workbench", "phase workflow")));
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
fn compact_idle_workbench_does_not_offer_an_abort_for_absent_work() {
    let target = tempfile::tempdir().unwrap();
    let workspace = kuzushi_core::WorkspaceTarget::new(target.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_shell_view(ShellView::Workbench);
    app.set_viewport(crate::TerminalViewport::new(40, 15));
    app.begin_guided_scan_questions();

    let bindings = footer_keybindings(&app);

    assert!(bindings.contains(&bind("Ctrl+C", "exit")), "{bindings:?}");
    assert!(!bindings.contains(&bind("Ctrl+C", "request abort")));
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
    assert_eq!(count_binding(&bindings, "scan", "Scan phase planner"), 0);
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
        .set_focus(PhaseSurfaceId::ReviewQueue);

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

    assert!(bindings.contains(&bind("KEYS", "↑/↓ move")));
    assert!(bindings.contains(&bind("←/→", "phase")));
    assert!(bindings.contains(&bind("Tab/Shift+Tab", "focus pane")));
    assert!(bindings.contains(&bind("type", "command")));
    assert!(bindings.contains(&bind("Esc", "workbench")));
    assert!(!bindings.iter().any(|binding| binding.key.contains('j')));
    assert!(!bindings.iter().any(|binding| binding.key.contains('q')));
    assert!(!bindings.contains(&bind("Esc", "close")));
    assert!(!bindings.contains(&bind("workbench", "phase workflow")));

    app.engagement
        .planning_picker_mut()
        .set_focus(crate::app::PickerFocus::OptionsPane);
    let bindings = footer_keybindings(&app);

    assert!(bindings.contains(&bind("KEYS", "↑/↓ option")));
    assert!(bindings.contains(&bind("Tab/Shift+Tab", "steps")));
    assert!(bindings.contains(&bind("type", "command")));
    assert!(bindings.contains(&bind("Esc", "steps")));
    assert!(!bindings.contains(&bind("workbench", "phase workflow")));
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
            bindings.contains(&bind("j/k/↑/↓", "scroll")),
            "{view:?} footer should show scroll keys"
        );
        assert!(
            bindings.contains(&bind("g/G", "ends")),
            "{view:?} footer should show edge keys"
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
        assert!(!bindings.contains(&bind("j/k/↑/↓", "scroll")), "{view:?}");
        assert!(!bindings.contains(&bind("g/G", "ends")), "{view:?}");
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
    assert!(!prompt.contains(&bind("j/k/↑/↓", "scroll")));
    assert!(!prompt.contains(&bind("g/G", "ends")));

    app.set_input_mode(crate::InputMode::Navigate);
    let navigate = footer_keybindings(&app);
    assert!(navigate.contains(&bind("j/k/↑/↓", "scroll")));
    assert!(navigate.contains(&bind("g/G", "ends")));
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
    // The DFD selects topology separately from its wrapped detail viewport.
    assert!(dfd_bindings.contains(&bind("j/k/↑/↓", "select")));
    assert!(dfd_bindings.contains(&bind("Enter", "generate DFD")));
    assert!(dfd_bindings.contains(&bind("PgUp/PgDn", "detail")));
    assert!(!dfd_bindings.contains(&bind("j/k/↑/↓", "scroll")));
    assert!(!dfd_bindings.contains(&bind("g/G", "ends")));
    assert!(!dfd_bindings.contains(&bind("Tab", "next page")));
    assert!(!dfd_bindings.contains(&bind("Shift+Tab", "prev page")));
    assert!(dfd_bindings.contains(&bind("Esc/q", "leave")));
    assert!(!dfd_bindings.contains(&bind("h/l/j/k", "orbit 3D")));
    assert!(!dfd_bindings.contains(&bind("space/p", "pause")));
    assert!(!dfd_bindings.contains(&bind("r", "reset")));

    app.router.scene_mut().set_page(VizPage::Summary);
    let summary_bindings = footer_keybindings(&app);
    assert!(summary_bindings.contains(&bind("PgUp/PgDn", "scroll")));
    assert!(summary_bindings.contains(&bind("j/k/↑/↓", "component")));
    assert!(summary_bindings.contains(&bind("g/G", "ends")));
    assert!(summary_bindings.contains(&bind("Enter", "DFD target")));
    app.router.scene_mut().set_page(VizPage::Dfd);

    app.router.scene_mut().toggle_dfd_focus();
    let focused_bindings = footer_keybindings(&app);
    assert!(focused_bindings.contains(&bind("j/k/↑/↓", "context")));
    assert!(focused_bindings.contains(&bind("Enter", "topology")));
    assert!(focused_bindings.contains(&bind("Esc", "collapse")));
    assert!(focused_bindings.contains(&bind("q", "leave")));
    assert!(!focused_bindings.contains(&bind("Esc/q", "leave")));
    app.router.scene_mut().toggle_dfd_focus();

    app.router.scene_mut().set_page(VizPage::AttackSurface);
    app.set_shell_view(ShellView::Scene);
    let terrain_bindings = footer_keybindings(&app);
    assert!(!terrain_bindings.contains(&bind("j/k/↑/↓", "scroll")));
    assert!(!terrain_bindings.contains(&bind("g/G", "ends")));
    assert!(terrain_bindings.contains(&bind("h/l/j/k", "orbit 3D")));
    assert!(terrain_bindings.contains(&bind("space/p", "pause")));
    assert!(terrain_bindings.contains(&bind("r", "reset")));

    app.router.scene_mut().set_page(VizPage::AttackPath);
    let path_bindings = footer_keybindings(&app);
    assert!(path_bindings.contains(&bind("j/k/↑/↓", "scroll")));
    assert!(path_bindings.contains(&bind("g/G", "ends")));

    app.router.scene_mut().set_page(VizPage::EntryPoints);
    let entry_bindings = footer_keybindings(&app);
    assert!(entry_bindings.contains(&bind("j/k", "select")));
    assert!(entry_bindings.contains(&bind("g/G", "ends")));
    assert!(entry_bindings.contains(&bind("PgUp/PgDn", "detail")));
    assert!(entry_bindings.contains(&bind("Enter", "DFD target")));
    assert!(!entry_bindings.contains(&bind("j/k/↑/↓", "scroll")));
}

#[test]
fn scene_footer_never_advertises_prompt_completion_for_page_cycle_tab() {
    let mut app = ShellApp::new(V2Config::default(), None);
    *app.findings_mut() = vec![kuzushi_core::Finding::new_semgrep(
        "rule.high",
        "src/auth/login.rs",
        10,
        Some(10),
        kuzushi_core::Severity::High,
        "auth bug",
    )];
    app.router.scene_mut().set_page(VizPage::Dfd);
    app.set_shell_view(ShellView::Scene);
    app.set_input_mode(crate::InputMode::Prompt);

    let bindings = footer_keybindings(&app);

    assert!(bindings.contains(&bind("Tab", "next page")));
    assert!(!bindings.contains(&bind("Tab", "complete")));
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
