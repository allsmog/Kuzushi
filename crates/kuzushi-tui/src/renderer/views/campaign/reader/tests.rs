use super::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use kuzushi_core::V2Config;
use ratatui::{backend::TestBackend, Terminal};

fn reader(width: u16, height: u16) -> ShellApp {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Campaign);
    app.set_input_mode(crate::InputMode::Navigate);
    app.set_viewport(crate::TerminalViewport::new(width, height));
    app.router.campaign_mut().notice = Some(
        (0..20)
            .map(|index| format!("observation-{index:02}"))
            .collect::<Vec<_>>()
            .join("\n"),
    );
    app
}

fn press(app: &mut ShellApp, code: KeyCode) {
    assert!(
        app.reduce_key(KeyEvent::new(code, KeyModifiers::NONE))
            .handled
    );
}

fn draw(app: &ShellApp) -> String {
    let size = app.viewport();
    let mut terminal = Terminal::new(TestBackend::new(size.columns, size.rows)).unwrap();
    terminal
        .draw(|frame| crate::renderer::render_app(frame, app))
        .unwrap();
    let buffer = terminal.backend().buffer();
    buffer
        .content
        .chunks(size.columns as usize)
        .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn paging_reaches_every_observation_in_the_viewport_matrix() {
    for (width, height) in [(40, 12), (60, 20), (80, 24), (120, 36), (160, 48), (96, 89)] {
        let mut app = reader(width, height);
        let mut seen = String::new();
        for _ in 0..40 {
            seen.push_str(&draw(&app));
            press(&mut app, KeyCode::PageDown);
        }
        for index in 0..20 {
            assert!(
                seen.contains(&format!("observation-{index:02}")),
                "{width}x{height}: {seen}"
            );
        }
        if height == 12 {
            assert!(seen.contains("PgUp/PgDn"), "{seen}");
        }
    }
}

#[test]
fn paging_recovers_from_the_tail_and_resize_without_changing_selection_or_draft() {
    let mut app = reader(40, 12);
    app.set_input("held operator draft");
    press(&mut app, KeyCode::Char('G'));
    press(&mut app, KeyCode::PageUp);
    let max = campaign_reader_scroll(&app).unwrap().max_offset;
    assert!(app.router.campaign().read_scroll < max);
    for _ in 0..100 {
        press(&mut app, KeyCode::PageDown);
    }
    assert_eq!(app.router.campaign().read_scroll, max);
    app.set_viewport(crate::TerminalViewport::new(80, 24));
    press(&mut app, KeyCode::PageUp);
    assert!(app.router.campaign().read_scroll < campaign_reader_scroll(&app).unwrap().max_offset);
    assert_eq!(app.router.campaign().selected_job, 0);
    assert_eq!(app.router.campaign().selected_campaign, 0);
    assert_eq!(app.input(), "held operator draft");
}
