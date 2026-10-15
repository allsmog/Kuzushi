use super::*;
use kuzushi_core::V2Config;
use ratatui::{backend::TestBackend, Terminal};

#[test]
fn halted_budget_editor_keeps_unknown_spend_and_the_field_visible() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.session_mut().set_session_budget_usd(Some(1.0));
    app.record_cost_report(kuzushi_core::runtime::RuntimeCostReport::INCOMPLETE_ZERO);
    app.set_shell_view(ShellView::Setup);
    app.router.setup_mut().begin_budget_edit(Some(1.0));
    app.reduce_key(crossterm::event::KeyEvent::new(
        crossterm::event::KeyCode::Char('u'),
        crossterm::event::KeyModifiers::CONTROL,
    ));
    app.reduce_paste("12.345");
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.set_viewport(crate::TerminalViewport::new(width, height));
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let buffer = terminal.backend().buffer();
        let text = (0..height)
            .map(|y| {
                (0..width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        for expected in ["12.345", "metering incomplete", "Enter save", "Esc cancel"] {
            assert!(
                text.contains(expected),
                "missing {expected} at {width}x{height}: {text}"
            );
        }
    }
}

#[test]
fn budget_editor_field_validation_and_save_cancel_stay_visible() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let target = tempfile::tempdir().unwrap();
    app.set_target(Some(target.path().into()));
    app.set_shell_view(ShellView::Setup);
    app.router.setup_mut().set_cursor(6);
    app.router.setup_mut().begin_budget_edit(None);
    app.reduce_paste("12.345");
    app.router
        .setup_mut()
        .set_budget_error("Amount exceeds hard ceiling $10.12345");
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let buffer = terminal.backend().buffer();
        let text = (0..height)
            .map(|y| {
                (0..width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        for expected in [
            "12.345",
            "hard ceiling $10.12345",
            "Enter save",
            "Esc cancel",
            "Observed spend stop",
            "overspend.",
        ] {
            assert!(
                text.contains(expected),
                "missing {expected} at {width}x{height}: {text}"
            );
        }
        assert!(
            !text.contains("Start Map"),
            "editing must show edit controls: {text}"
        );
        assert!(
            !text.contains("moves the picker"),
            "budget owns focus: {text}"
        );
    }
}

#[test]
fn budget_editor_long_invalid_draft_keeps_the_cursor_and_controls_reachable() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::style::Modifier;
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Setup);
    app.router.setup_mut().begin_budget_edit(None);
    let draft = format!("START{}東京END", "1234567890".repeat(30));
    app.reduce_paste(&draft);
    app.reduce_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    for (key, expected) in [(KeyCode::End, "東京END"), (KeyCode::Home, "START")] {
        app.reduce_key(KeyEvent::new(key, KeyModifiers::CONTROL));
        let lines = budget_editor_lines(&app, Rect::new(0, 0, 40, 10));
        let text = lines
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains(expected), "{text}");
        assert!(text.contains("Enter save") && text.contains("Esc cancel"));
        assert!(text.contains("Enter one positive USD amount"));
        assert!(lines.len() <= 10);
        assert!(lines.iter().all(|line| line.width() <= 40));
        assert!(lines
            .iter()
            .flat_map(|line| &line.spans)
            .any(|span| span.style.add_modifier.contains(Modifier::REVERSED)));
        assert_eq!(app.router.setup().budget_draft(), draft);
    }
}
