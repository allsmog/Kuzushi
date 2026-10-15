use super::*;
use ratatui::{backend::TestBackend, Terminal};

#[test]
fn compact_map_navigation_reserves_content_and_restores_chrome_for_decisions() {
    let target = tempfile::tempdir().unwrap();
    seed_ready_map_target(target.path(), "compact-map-navigation");
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(target.path().to_path_buf()));
    app.refresh_phase_attempt_projection();
    app.hydrate_all_view_data_for_test();
    app.set_workbench_page(WorkbenchPage::Map);
    app.set_input_mode(InputMode::Navigate);
    app.set_viewport(crate::TerminalViewport::new(40, 12));
    assert!(crate::ui_view_models::compact_phase_reading(&app, 12));
    let first = render_summary(&app, 40, 12);
    assert!(first.contains("Operators use Sample"), "{first}");
    assert!(first.contains("SYSTEM SUMMARY"), "{first}");
    assert!(first.contains("PgUp/PgDn read"), "{first}");
    assert!(first.contains("Enter DFD"), "{first}");
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE),
    );
    assert_ne!(first, render_summary(&app, 40, 12));
    app.advisory_mut().pending_confirm = Some(crate::PendingConfirm {
        kind: crate::ConfirmKind::DescriptorEffect,
        tool: "workspace:export-findings".into(),
        target: "owned export".into(),
        actor: None,
        rationale: None,
        allowlist: None,
        remembered: false,
    });
    assert!(!crate::ui_view_models::compact_phase_reading(&app, 12));
    app.advisory_mut().pending_confirm = None;
    app.set_input("preserved operator draft");
    assert!(!crate::ui_view_models::compact_phase_reading(&app, 12));
    assert_eq!(app.input(), "preserved operator draft");
}

#[test]
fn smallest_map_summary_shows_context_and_pages_without_skipping_hidden_rows() {
    let target = tempfile::tempdir().unwrap();
    seed_ready_map_target(target.path(), "compact-map-summary");
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(target.path().to_path_buf()));
    app.refresh_phase_attempt_projection();
    app.hydrate_all_view_data_for_test();
    app.set_workbench_page(WorkbenchPage::Map);
    app.set_input_mode(InputMode::Prompt);
    app.set_viewport(crate::TerminalViewport::new(40, 12));

    let first = render_summary(&app, 40, 12);
    assert!(first.contains("Operators use Sample"), "{first}");
    press_key(&mut app, KeyEvent::new(KeyCode::PageUp, KeyModifiers::NONE));
    assert_eq!(first, render_summary(&app, 40, 12));
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE),
    );
    assert_eq!(app.router.scene().summary_scroll(), 1);
    let next = render_summary(&app, 40, 12);
    assert_ne!(first, next);
    assert!(next.contains("records."), "{next}");

    press_key(&mut app, KeyEvent::new(KeyCode::PageUp, KeyModifiers::NONE));
    assert_eq!(app.router.scene().summary_scroll(), 0);
    assert_eq!(first, render_summary(&app, 40, 12));
    assert!(app.input().is_empty());
}

#[test]
fn summary_paging_keeps_the_existing_step_when_the_viewport_has_room() {
    let target = tempfile::tempdir().unwrap();
    seed_ready_map_target(target.path(), "roomy-map-summary");
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(target.path().to_path_buf()));
    app.refresh_phase_attempt_projection();
    app.hydrate_all_view_data_for_test();
    app.set_workbench_page(WorkbenchPage::Map);
    app.set_viewport(crate::TerminalViewport::new(120, 36));

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE),
    );
    assert_eq!(
        app.router.scene().summary_scroll(),
        VIEWPORT_PAGE_LINES as i32
    );
}

fn render_summary(app: &ShellApp, width: u16, height: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal
        .draw(|frame| crate::render_app(frame, app))
        .unwrap();
    let buffer = terminal.backend().buffer();
    (0..height)
        .map(|row| {
            (0..width)
                .map(|column| buffer[(column, row)].symbol())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}
