use super::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

fn comparison_app(root: &std::path::Path, count: usize) -> ShellApp {
    let rows = (0..count)
        .map(|index| {
            serde_json::json!({
                "identityId": format!("fi_{index:03}"), "title": format!("observation {index:03}"),
                "severity": "medium", "filePath": "src/app.rs", "startLine": index + 1,
                "tool": "semgrep"
            })
        })
        .collect::<Vec<_>>();
    for run in ["base", "later"] {
        write_run_diff_fixture(root, run, &"a".repeat(40), serde_json::json!(rows));
    }
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(root.to_path_buf()));
    app.router.run_diff_mut().open("base", "later");
    app.set_shell_view(ShellView::RunDiff);
    app.hydrate_active_view_blocking();
    app
}

fn key(app: &mut ShellApp, code: KeyCode) {
    press_key(app, KeyEvent::new(code, KeyModifiers::NONE));
}

#[test]
fn cold_or_unavailable_comparisons_never_display_zero_as_a_recorded_result() {
    let root = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(root.path().into()));
    app.router
        .run_diff_mut()
        .open("missing-base", "missing-later");
    app.set_shell_view(ShellView::RunDiff);
    for hydrated in [false, true] {
        if hydrated {
            app.hydrate_active_view_blocking();
        }
        let text = render_plain_app(&app, 80);
        assert!(text.contains("Comparison counts are pending."), "{text}");
        assert!(!text.contains("+0 new"), "{text}");
        assert!(!text.contains("0 not observed"), "{text}");
    }
}

#[test]
fn run_diff_tab_preserves_each_scroll_and_yields_to_the_composer() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = comparison_app(temp.path(), 30);
    app.set_input_mode(crate::InputMode::Prompt);
    let bindings = crate::ui_view_models::footer_keybindings(&app);
    assert!(bindings
        .iter()
        .any(|binding| binding.key == "Tab" && binding.label == "findings / sources"));
    assert!(!bindings.iter().any(|binding| binding.label == "complete"));
    app.router.default_scroll_mut().set(9);
    key(&mut app, KeyCode::Tab);
    assert!(app.router.run_diff().sources_open());
    assert_eq!(app.router.default_scroll().offset(), 0);
    app.router.default_scroll_mut().set(3);
    key(&mut app, KeyCode::BackTab);
    assert!(!app.router.run_diff().sources_open());
    assert_eq!(app.router.default_scroll().offset(), 9);
    key(&mut app, KeyCode::Tab);
    assert_eq!(app.router.default_scroll().offset(), 3);

    app.set_input("my multiline\ndraft");
    assert!(crate::ui_view_models::footer_keybindings(&app)
        .iter()
        .any(|binding| binding.key == "Tab" && binding.label == "complete"));
    key(&mut app, KeyCode::Left);
    let cursor = app.cursor();
    key(&mut app, KeyCode::BackTab);
    assert!(app.router.run_diff().sources_open());
    assert_eq!(app.input(), "my multiline\ndraft");
    assert_eq!(app.cursor(), cursor);
}

#[test]
fn run_diff_leads_with_outcome_and_keeps_tabs_reachable_at_every_viewport() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = comparison_app(temp.path(), 30);
    app.set_input_mode(crate::InputMode::Navigate);
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.set_viewport(crate::TerminalViewport {
            columns: width,
            rows: height,
        });
        app.router.default_scroll_mut().reset();
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let top = format!("{:?}", terminal.backend().buffer());
        assert!(top.contains("[Findings]"), "{width}x{height}: {top}");
        if width >= 60 {
            assert!(
                top.contains("Absence does not establish a fix."),
                "{width}x{height}: {top}"
            );
        }
        key(&mut app, KeyCode::Char('G'));
        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let end = format!("{:?}", terminal.backend().buffer());
        assert!(end.contains("[Findings]"));
        assert!(
            end.contains("observation 029"),
            "tail at {width}x{height}: {end}"
        );
        key(&mut app, KeyCode::Tab);
        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        assert!(format!("{:?}", terminal.backend().buffer()).contains("[Sources & context]"));
        key(&mut app, KeyCode::BackTab);
    }
}

#[test]
fn run_diff_plain_includes_all_observations_and_provenance_regardless_of_tab_or_scroll() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = comparison_app(temp.path(), 30);
    for sources in [false, true] {
        if sources {
            app.router.run_diff_mut().toggle_sources(7);
        }
        app.router.default_scroll_mut().tail();
        let text = render_plain_app(&app, 80);
        assert!(text.contains("observation 000"));
        assert!(text.contains("observation 029"));
        assert!(text.contains(&"a".repeat(40)));
        assert!(text.contains("Base threat model:"));
        assert!(!text.contains('\u{1b}'));
    }
}

#[test]
fn run_diff_new_pair_resets_both_tabs() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = comparison_app(temp.path(), 30);
    key(&mut app, KeyCode::Tab);
    run_command(
        &mut app,
        crate::commands::ShellCommand::RunDiff {
            left: "later".to_string(),
            right: "newer".to_string(),
        },
    );
    assert!(!app.router.run_diff().sources_open());
    assert_eq!(app.router.default_scroll().offset(), 0);
    key(&mut app, KeyCode::Tab);
    assert_eq!(app.router.default_scroll().offset(), 0);
}

fn review_comparison_app(root: &std::path::Path) -> ShellApp {
    let mut app = comparison_app(root, 1);
    let mut finding = kuzushi_core::Finding::new_tool(
        "secret-scan",
        "rule",
        "src/app.rs",
        1,
        None,
        kuzushi_core::Severity::High,
        "Review source evidence",
    );
    finding.observation_gap = Some(kuzushi_core::findings::FindingObservationGap {
        event_seq: 5,
        event_hash: "gap-receipt".into(),
        last_seen_run_id: Some("base".into()),
        compared_run_id: Some("later".into()),
    });
    app.set_findings(vec![finding]);
    app.set_shell_view(ShellView::Workbench);
    app.router
        .workbench_mut()
        .set_page(Some(crate::app::WorkbenchPage::Review));
    let surface = crate::ui_view_models::PhaseSurfaceId::ReviewDetail;
    app.router.workbench_mut().set_focus(surface);
    app.router.workbench_mut().toggle_zoom(surface);
    app.router.workbench_mut().scroll_mut().set(surface, 7);
    app.set_input_mode(crate::InputMode::Navigate);
    app.sync_view_change();
    app
}

#[test]
fn review_comparison_returns_to_the_same_finding_focus_zoom_and_scroll() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = review_comparison_app(temp.path());
    let mut unrelated = app.findings()[0].clone();
    unrelated.fingerprint = "pinned-outside-the-visible-row".into();
    unrelated.observation_gap.as_mut().unwrap().compared_run_id = Some("wrong-run".into());
    app.set_selected_finding(Some(unrelated));
    let before = app.router.workbench().clone();
    let cursor = app.router.findings().cursor();
    key(&mut app, KeyCode::Char('v'));
    assert_eq!(app.shell_view(), ShellView::RunDiff);
    assert_eq!(app.router.run_diff().right(), "later");
    assert!(app.router.run_diff().sources_open());
    app.sync_view_change();
    key(&mut app, KeyCode::Tab);
    app.router.default_scroll_mut().set(4);
    key(&mut app, KeyCode::Esc);
    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(app.router.workbench(), &before);
    assert_eq!(app.router.findings().cursor(), cursor);
    assert_eq!(
        app.router
            .findings()
            .selected_finding()
            .as_ref()
            .unwrap()
            .fingerprint,
        "pinned-outside-the-visible-row"
    );
    assert_eq!(app.input_mode(), crate::InputMode::Navigate);
}

#[test]
fn review_comparison_yields_to_a_multiline_draft_and_requires_recorded_runs() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = review_comparison_app(temp.path());
    app.set_input_mode(crate::InputMode::Prompt);
    app.set_input("First line\nsecond line");
    key(&mut app, KeyCode::Left);
    let cursor = app.cursor();
    key(&mut app, KeyCode::Char('v'));
    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(app.cursor(), cursor + 1);
    assert!(app.input().contains('\n'));
    let mut finding = app.findings()[0].clone();
    finding.observation_gap.as_mut().unwrap().last_seen_run_id = None;
    app.set_findings(vec![finding]);
    assert!(app.review_observation_run_pair().is_none());
    assert!(!app
        .view_keybindings()
        .iter()
        .any(|binding| binding.label == "compare scans"));
}
