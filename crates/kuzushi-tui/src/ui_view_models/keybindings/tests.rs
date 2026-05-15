use super::*;
use crate::{ScanPanelState, ShellView};
use kuzushi_core::V2Config;
use std::path::PathBuf;

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
