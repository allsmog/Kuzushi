use super::*;
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
        ShellView::Patch("F-0001".to_string()),
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
fn finding_detail_advertises_esc_not_a_typed_verb() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Finding;
    let bindings = footer_keybindings(&app);
    assert!(bindings.contains(&bind("Esc", "back to list")));
    assert!(!bindings.contains(&bind("findings", "list")));
}

#[test]
fn footer_keybindings_include_shell_completion_prefix() {
    let app = ShellApp::new(V2Config::default(), None);

    let bindings = footer_keybindings(&app);

    assert_eq!(bindings[0], bind("Tab", "complete"));
    assert!(bindings.contains(&bind("modules", "browse")));
    assert!(bindings.contains(&bind("Ctrl+C", "exit")));
}

#[test]
fn footer_keybindings_show_scan_abort_action_when_running() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.scan = Some(scan_state(true, false));

    let bindings = footer_keybindings(&app);

    assert_eq!(bindings[0], bind("Ctrl+C", "request abort"));
    assert!(bindings.contains(&bind("findings", "list")));
    assert!(!bindings.contains(&bind("Tab", "complete")));
}

#[test]
fn footer_keybindings_show_arm_exit_after_abort_request() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.scan = Some(scan_state(true, true));

    let bindings = footer_keybindings(&app);

    assert_eq!(bindings[0], bind("Ctrl+C", "arm exit"));
}

#[test]
fn footer_keybindings_deduplicate_view_bindings() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Findings;
    app.findings = vec![kuzushi_core::Finding::new_semgrep(
        "demo.rule",
        "src/app.rs",
        1,
        Some(1),
        kuzushi_core::Severity::High,
        "demo",
    )];

    let bindings = footer_keybindings(&app);

    assert_eq!(count_binding(&bindings, "j/k/g/G", "move"), 1);
    assert_eq!(count_binding(&bindings, "scan", "rescan"), 1);
}

#[test]
fn previously_empty_views_now_show_scroll_and_back_in_footer() {
    for view in [
        ShellView::Tools,
        ShellView::History,
        ShellView::Context,
        ShellView::KnowledgeBase,
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
