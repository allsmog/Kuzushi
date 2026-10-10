use super::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use kuzushi_core::V2Config;
use ratatui::{backend::TestBackend, Terminal};

#[test]
fn every_study_row_stays_selected_and_reachable_at_all_viewports() {
    let root = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(root.path().to_path_buf()));
    app.open_batch_scan_config(None);
    app.set_input("preserved\ndraft");
    app.set_cursor(4);
    for (width, height) in [(40, 12), (60, 20), (80, 24), (120, 36), (160, 48), (96, 89)] {
        app.reduce_resize(width, height);
        for index in 0..BatchScanConfigRow::ALL.len() {
            app.router
                .campaign_mut()
                .batch_scan_config
                .as_mut()
                .unwrap()
                .cursor = index;
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            terminal
                .draw(|frame| crate::renderer::render_app(frame, &app))
                .unwrap();
            let text = format!("{:?}", terminal.backend().buffer());
            let label = BatchScanConfigRow::ALL[index].label();
            assert!(
                text.contains(label),
                "{width}x{height} lost {label}: {text}"
            );
            assert!(text.contains("L next"), "{text}");
            assert!(text.contains("Esc back"), "{text}");
            app.reduce_key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE));
        }
    }
    assert_eq!((app.input(), app.cursor()), ("preserved\ndraft", 4));
}

#[test]
fn numeric_editor_preserves_error_and_controls_at_forty_columns() {
    let root = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(root.path().to_path_buf()));
    app.open_batch_scan_config(None);
    app.reduce_resize(40, 12);
    let config = app
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap();
    config.begin_number_edit(BatchScanConfigRow::ProviderCalls);
    app.reduce_paste("1\n999");
    app.reduce_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    let mut terminal = Terminal::new(TestBackend::new(40, 12)).unwrap();
    terminal
        .draw(|frame| crate::renderer::render_app(frame, &app))
        .unwrap();
    let text = format!("{:?}", terminal.backend().buffer());
    for expected in [
        "Total calls",
        "whole number",
        "Enter save",
        "Esc cancel",
        "Saving starts no work",
    ] {
        assert!(text.contains(expected), "missing {expected}: {text}");
    }
}

#[test]
fn study_failure_is_readable_and_dismisses_without_losing_the_draft() {
    let root = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(root.path().to_path_buf()));
    app.open_batch_scan_config(None);
    app.reduce_resize(40, 12);
    app.set_input("keep my draft");
    app.set_error_notice(
        "tool",
        "Unknown scan task. Select a supported scanner before preparing the draft.",
    );
    app.study_preparation_failed(
        "campaign:study",
        "Unknown scan task. Select a supported scanner before preparing the draft.",
    );
    app.clear_notice();
    for (width, height) in [(40, 12), (60, 20), (80, 24), (120, 36), (160, 48), (96, 89)] {
        app.reduce_resize(width, height);
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let text = format!("{:?}", terminal.backend().buffer());
        assert!(text.contains("ATTENTION: Unknown scan task"), "{text}");
        assert!(text.contains("Esc dismiss"));
    }
    let plain = crate::renderer::render_plain_app(&app, 80);
    assert!(plain.contains("ATTENTION: Unknown scan task"), "{plain}");
    let blocked = app.reduce_key(KeyEvent::new(KeyCode::Char('L'), KeyModifiers::NONE));
    assert!(blocked.effects.is_empty());
    app.reduce_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(app.batch_config_open());
    assert!(!app.notice_captures_escape());
    assert!(!app.study_notice_captures_escape());
    assert_eq!(app.input(), "keep my draft");
}

#[test]
fn expanded_detail_names_the_selected_setting_and_keeps_return_controls_visible() {
    let target = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(target.path().to_path_buf()));
    app.open_batch_scan_config(None);
    app.router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .cursor = 3;
    app.reduce_key(KeyEvent::new(KeyCode::Char('z'), KeyModifiers::NONE));
    for (width, height) in [(40, 12), (60, 20), (80, 24), (120, 36), (160, 48), (96, 89)] {
        app.reduce_resize(width, height);
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let text = format!("{:?}", terminal.backend().buffer());
        for label in ["Source and context", "z form", "↑↓/PgUp/Dn", "PgUp/Dn"] {
            assert!(
                text.contains(label),
                "{width}x{height} lost {label}: {text}"
            );
        }
        assert!(!text.contains("Discovery passes"));
    }
    let plain = crate::renderer::render_plain_app(&app, 40);
    assert!(plain.contains("Source and context"));
    assert!(!plain.contains("Discovery passes"));
    assert!(plain.contains("Allowance not approved"));
}
