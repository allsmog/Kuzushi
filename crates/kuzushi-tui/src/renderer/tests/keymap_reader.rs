use super::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

fn reader(width: u16, height: u16) -> ShellApp {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_activity(Some(ActivitySession::new("keymap-origin")));
    app.set_shell_view(ShellView::Activity);
    app.set_input("held operator draft");
    app.set_shell_view(ShellView::Keymap);
    app.set_input_mode(crate::InputMode::Prompt);
    app.set_viewport(crate::TerminalViewport::new(width, height));
    app
}

fn populate(app: &mut ShellApp) {
    let model = crate::ui_view_models::keymap_model(app);
    let rows = (0..50)
        .map(|i| {
            crate::KeymapBindingRow::new(
                "Ctrl+Shift+Alt+F12 / Ctrl+Shift+Alt+F11",
                format!("action-row-{i:02} retains its complete description and résumé"),
            )
        })
        .collect();
    app.replace_keymap_snapshot_for_test(Some(crate::KeymapSnapshot {
        status: model.status,
        event_time: model.event_time,
        sections: vec![crate::KeymapSection::new(
            "READER",
            "complete fixture controls",
            rows,
        )],
        note: model.note,
        footer: model.footer,
    }));
}

fn press(app: &mut ShellApp, code: KeyCode) {
    assert!(
        app.reduce_key(KeyEvent::new(code, KeyModifiers::NONE))
            .handled
    );
}

fn draw(app: &ShellApp) -> Vec<String> {
    let size = app.viewport();
    let mut terminal = Terminal::new(TestBackend::new(size.columns, size.rows)).unwrap();
    terminal.draw(|frame| render_app(frame, app)).unwrap();
    rendered_buffer_rows(terminal.backend().buffer())
}

fn body(app: &ShellApp) -> Vec<String> {
    draw(app)
        .into_iter()
        .filter(|line| line.trim_start().starts_with('│'))
        .collect()
}

#[test]
fn keymap_reader_compact_view_has_six_reading_rows_and_current_controls_first() {
    let app = reader(40, 12);
    let rows = draw(&app);
    assert!(body(&app).len() >= 6, "{rows:?}");
    assert!(rows.join("\n").contains("VIEW · Activity"), "{rows:?}");
    assert!(rows.join("\n").contains("Esc/q close"), "{rows:?}");
    assert!(!rows.join("\n").contains("NAVIGATION MODE"), "{rows:?}");
}

#[test]
fn keymap_reader_pages_preserve_every_action_and_complete_key_labels() {
    for (width, height) in [(40, 12), (80, 24)] {
        let mut app = reader(width, height);
        populate(&mut app);
        let mut seen = String::new();
        for _ in 0..100 {
            seen.push_str(&body(&app).join("\n"));
            press(&mut app, KeyCode::PageDown);
        }
        for index in 0..50 {
            assert!(
                seen.contains(&format!("action-row-{index:02}")),
                "missing action {index} at {width}x{height}"
            );
        }
        assert!(seen.contains("Ctrl+Shift+Alt+F12"));
        assert!(seen.contains("Ctrl+Shift+Alt+F11"));
        assert!(seen.contains("résumé"));
    }
}

#[test]
fn keymap_reader_recovers_from_tail_overscroll_and_resize() {
    let mut app = reader(40, 12);
    populate(&mut app);
    press(&mut app, KeyCode::Char('G'));
    let tail = body(&app);
    press(&mut app, KeyCode::Char('k'));
    assert_ne!(body(&app), tail);
    for _ in 0..300 {
        press(&mut app, KeyCode::Char('j'));
    }
    let end = body(&app);
    press(&mut app, KeyCode::PageUp);
    assert_ne!(body(&app), end);
    press(&mut app, KeyCode::Char('G'));
    app.set_viewport(crate::TerminalViewport::new(80, 24));
    let resized = body(&app);
    press(&mut app, KeyCode::Char('k'));
    assert_ne!(body(&app), resized);
}

#[test]
fn keymap_reader_returns_to_origin_without_consuming_the_held_draft() {
    let mut app = reader(40, 12);
    press(&mut app, KeyCode::PageDown);
    press(&mut app, KeyCode::Esc);
    assert_eq!(app.shell_view(), ShellView::Activity);
    assert_eq!(app.activity().unwrap().run_id, "keymap-origin");
    assert_eq!(app.input(), "held operator draft");
}

#[test]
fn keymap_reader_keeps_the_actual_long_remapped_binding() {
    let mut app = reader(40, 12);
    let overrides = [kuzushi_core::config::KeybindingOverrideConfig {
        context: "run_focus".into(),
        action: "cycle_pane".into(),
        bindings: vec!["ctrl+shift+alt+right".into()],
    }];
    app.ui_mut()
        .replace_runtime_keymap(crate::app::RuntimeKeymap::from_config(&overrides))
        .unwrap();
    let mut seen = String::new();
    for _ in 0..8 {
        seen.push_str(&body(&app).join("\n"));
        press(&mut app, KeyCode::PageDown);
    }
    assert!(seen.contains("ctrl+shift+alt+right"), "{seen}");
    assert!(seen.contains("toggle pane"), "{seen}");
}
