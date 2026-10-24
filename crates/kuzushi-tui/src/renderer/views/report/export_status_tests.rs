use super::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{backend::TestBackend, Terminal};

fn report_app(failed: bool) -> ShellApp {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.set_shell_view(crate::ShellView::Report);
    let route = app.router.report_mut();
    route.move_format(1);
    route.set_editing_path(true);
    route.edit_path_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
    route.insert_path_text(".kuzushi/reports/study-bundle");
    route.save_path_edit();
    route.set_receipt(crate::app::ReportReceipt {
        format: kuzushi_core::WorkspaceExportFormat::MarkdownBundle,
        completeness: kuzushi_core::WorkspaceExportCompleteness::All,
        count: (!failed).then_some(2),
        absolute_path: Some("/owned/.kuzushi/reports/study-bundle".into()),
        investigation_receipt_path: None,
        error: failed.then(|| "Owned export failure; source retained".into()),
        timestamp: "test".into(),
    });
    app.set_input("retained report draft λ");
    app.set_cursor(5);
    app.set_input_mode(crate::InputMode::Navigate);
    app
}

fn frame_text(app: &ShellApp, width: u16, height: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal
        .draw(|frame| crate::renderer::render_app(frame, app))
        .unwrap();
    let buffer = terminal.backend().buffer();
    (0..height)
        .map(|y| {
            (0..width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn export_outcome_and_destination_remain_visible_while_reading_at_every_size() {
    for (failed, expected) in [(false, "EXPORTED"), (true, "EXPORT FAILED")] {
        let mut app = report_app(failed);
        for (width, height) in [(40, 11), (60, 19), (80, 23), (96, 88), (120, 35), (160, 47)] {
            app.set_viewport(crate::TerminalViewport::new(width, height));
            for key in [KeyCode::Home, KeyCode::End] {
                app.reduce_key(KeyEvent::new(key, KeyModifiers::NONE));
                let text = frame_text(&app, width, height);
                assert!(text.contains(expected), "{width}x{height}: {text}");
                assert!(text.contains("study-bundle"), "{text}");
                let header = report_reader_header(&app, width);
                assert!(header[1].to_string().contains(expected));
                assert!(header.iter().all(|line| line.width() <= width as usize));
            }
        }
        assert_eq!((app.input(), app.cursor()), ("retained report draft λ", 5));
        let plain = crate::renderer::render_plain_app(&app, 40);
        assert!(plain.contains(expected) && !plain.contains('\u{1b}'));
    }
}

#[test]
fn editing_the_destination_or_changing_selection_clears_the_previous_outcome() {
    let mut app = report_app(false);
    app.router.report_mut().move_format(1);
    assert!(!report_destination_line(app.router.report(), 40)
        .to_string()
        .contains("EXPORTED"));
    app = report_app(true);
    app.router.report_mut().cycle_completeness();
    assert!(!report_destination_line(app.router.report(), 40)
        .to_string()
        .contains("EXPORT FAILED"));
    app = report_app(false);
    let route = app.router.report_mut();
    route.set_editing_path(true);
    route.insert_path_text("-new");
    route.save_path_edit();
    assert!(!report_destination_line(route, 40)
        .to_string()
        .contains("EXPORTED"));
    assert!(route.path_draft().ends_with("-new"));
}

#[test]
fn failed_report_exposes_the_destination_editor_without_claiming_a_current_read() {
    let mut app = report_app(true);
    for (width, height) in [(40, 11), (60, 19), (80, 23), (96, 88), (120, 35), (160, 47)] {
        app.set_viewport(crate::TerminalViewport::new(width, height));
        let text = frame_text(&app, width, height);
        let footer = text.lines().rev().take(3).collect::<Vec<_>>().join(" ");
        assert!(
            footer.contains("e path") || footer.contains("e edit path"),
            "{width}x{height}: {text}"
        );
        assert!(footer.contains("Enter not ready"), "{text}");
    }
    app.set_viewport(crate::TerminalViewport::new(40, 11));
    app.reduce_key(KeyEvent::new(KeyCode::Char('e'), KeyModifiers::NONE));
    assert!(app.router.report().editing_path());
    let text = frame_text(&app, 40, 11);
    assert!(text.contains("EXPORT DESTINATION"));
    assert!(text.contains("save path"));
    assert_eq!((app.input(), app.cursor()), ("retained report draft λ", 5));
}
