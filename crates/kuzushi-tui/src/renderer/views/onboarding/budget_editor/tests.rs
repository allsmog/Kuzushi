use super::*;
use kuzushi_core::V2Config;
use ratatui::{backend::TestBackend, Terminal};

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
    for (width, height) in [(40, 12), (80, 24), (120, 36)] {
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
