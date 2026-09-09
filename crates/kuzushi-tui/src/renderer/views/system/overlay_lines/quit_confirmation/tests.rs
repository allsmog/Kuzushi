use super::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use kuzushi_core::V2Config;

fn app_with_disclosures() -> ShellApp {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_input("unsaved shell draft".to_string());
    let mut snapshot = crate::app::QuitConfirmSnapshot {
        status: crate::app::QuitConfirmStatus {
            target: ".".into(),
            ctx: "none".into(),
            model: "none".into(),
            module: "quit".into(),
            cost: "none".into(),
        },
        timestamp: "now".into(),
        warning_title: "CONFIRM SESSION EXIT".into(),
        warning_body:
            "No active work is running; the unsaved session state below will be discarded.".into(),
        sections: Vec::new(),
        default_line: "default · n/N/Esc · stay".into(),
        footer: crate::app::QuitConfirmFooter {
            stage: "idle".into(),
            findings: 0,
            keybinds: vec![
                ("y/Y".into(), "exit".into()),
                ("n/N/Esc".into(), "stay".into()),
            ],
            prompt_module: "quit".into(),
        },
    };
    snapshot.sections.push(crate::app::QuitConfirmSection::new(
        "NOT SAVED",
        (0..30)
            .map(|n| {
                format!(
                    "draft {n} · the complete explanation of this unsaved choice remains available"
                )
            })
            .collect(),
    ));
    app.router.set_quit_confirm_snapshot(Some(snapshot));
    app.set_shell_view(ShellView::QuitConfirm);
    app
}

#[test]
fn narrow_quit_overlay_wraps_disclosures_and_pins_actions_while_scrolling() {
    for origin in [None, Some(ShellView::Home)] {
        let mut app = app_with_disclosures();
        app.router.set_overlay_origin(origin);
        app.set_viewport(crate::TerminalViewport::new(80, 24));
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let first = format!("{:?}", terminal.backend().buffer());
        assert!(first.contains("CONFIRM SESSION EXIT"));
        assert!(first.contains("y/Y exit"));
        assert!(first.contains("n/N/Esc stay"));
        let update = app.reduce_key(KeyEvent::new(KeyCode::End, KeyModifiers::NONE));
        assert!(update.handled && update.effects.is_empty());
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let last = format!("{:?}", terminal.backend().buffer());
        assert!(
            last.contains("draft 29"),
            "scroll={}\n{last}",
            app.router.quit_confirm_scroll()
        );
        assert!(last.contains("y/Y exit"));
        assert!(last.contains("n/N/Esc stay"));
        assert_ne!(first, last);
        let before_up = app.router.quit_confirm_scroll();
        app.reduce_key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));
        assert!(app.router.quit_confirm_scroll() < before_up);
        app.reduce_key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE));
        assert_ne!(app.shell_view(), ShellView::QuitConfirm);
        assert_eq!(app.input(), "unsaved shell draft");
        assert_eq!(app.router.quit_confirm_scroll(), 0);
    }
}

#[test]
fn quit_actions_and_every_disclosure_are_reachable_at_constrained_sizes() {
    let mut app = app_with_disclosures();
    for width in [40, 60, 80, 120] {
        let mut text = String::new();
        for offset in 0..100 {
            app.router.set_quit_confirm_scroll(offset);
            let lines = quit_overlay_lines(&app, Rect::new(0, 0, width, 12));
            assert!(lines.len() <= 8);
            assert!(lines.iter().all(|line| line.width() <= width as usize));
            let page = lines
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n");
            assert!(page.contains("y/Y exit"));
            assert!(page.contains("n/N/Esc stay"));
            text.push_str(&page);
        }
        for n in 0..30 {
            assert!(text.contains(&format!("draft {n} ·")));
        }
    }
}

mod viewport;
