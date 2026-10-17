use super::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

const SIZES: [(u16, u16); 6] = [(160, 48), (120, 36), (96, 89), (80, 24), (60, 20), (40, 12)];

fn options_app(tool: &str, option: &str, width: u16, height: u16) -> ShellApp {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_viewport(crate::TerminalViewport::new(width, height));
    app.show_options(Some(tool.into()), crate::OptionsFilter::Standard);
    app.router.options_browser_mut().selected = Some(option.into());
    app
}

fn draw(app: &ShellApp, width: u16, height: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|frame| render_app(frame, app)).unwrap();
    rendered_buffer_rows(terminal.backend().buffer()).join("\n")
}

fn option_body_text(app: &ShellApp, width: u16, height: u16) -> String {
    let (page, _) = option_detail_page_bounds(app);
    draw(app, width, height)
        .lines()
        .skip(2)
        .take(page)
        .map(|line| line.split('│').next().unwrap())
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn options_selection_value_and_support_are_visible_in_every_viewport() {
    for (width, height) in SIZES {
        let app = options_app("x-ray:run", "baseUrl", width, height);
        let visible = draw(&app, width, height);
        assert!(
            visible.contains("Experimental"),
            "{width}x{height}: {visible}"
        );
        assert!(visible.contains("Value:"), "{width}x{height}: {visible}");
        assert!(visible.contains("Enter"), "{width}x{height}: {visible}");
    }
}

#[test]
fn preparation_limits_are_readable_without_hiding_the_selected_option() {
    for (width, height) in SIZES {
        let mut app = options_app("taint-iris-next:codeql-db", "target", width, height);
        let first = draw(&app, width, height);
        assert!(first.contains("Value:"), "{width}x{height}: {first}");
        let mut read = option_body_text(&app, width, height);
        for _ in 0..8 {
            app.reduce_key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE));
            read.push('\n');
            read.push_str(&option_body_text(&app, width, height));
        }
        for fact in [
            "whole bound target",
            "Context allowance",
            "execution consent",
            "No Map or Scan completion",
        ] {
            let normalized = read.split_whitespace().collect::<Vec<_>>().join(" ");
            assert!(
                normalized.contains(fact),
                "{width}x{height} missing {fact}: {read}"
            );
            assert!(
                plain_options_lines(&app, usize::from(width), app.router.options())
                    .join("\n")
                    .contains(fact)
            );
        }
        assert_eq!(app.selected_browser_option().as_deref(), Some("target"));
    }
}

#[test]
fn option_editor_cursor_draft_and_save_controls_survive_all_resizes() {
    let mut app = options_app("threat-model:ask", "question", 120, 36);
    app.reduce_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    app.reduce_paste("Operator α\nsecond line");
    let field = app
        .router
        .options_browser()
        .edit
        .as_ref()
        .unwrap()
        .field
        .clone();
    for (width, height) in SIZES {
        app.set_viewport(crate::TerminalViewport::new(width, height));
        let visible = draw(&app, width, height);
        assert!(
            visible.contains("EDIT Question"),
            "{width}x{height}: {visible}"
        );
        assert!(
            visible.contains("save session"),
            "{width}x{height}: {visible}"
        );
        assert!(
            visible.contains("second line"),
            "{width}x{height}: {visible}"
        );
        assert_eq!(
            app.router.options_browser().edit.as_ref().unwrap().field,
            field
        );
    }
}

#[test]
fn options_detail_page_stops_at_end_and_one_page_back_moves_immediately() {
    let mut app = options_app("threat-model:ask", "question", 40, 12);
    for _ in 0..100 {
        app.reduce_key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE));
    }
    let (page, maximum) = option_detail_page_bounds(&app);
    assert!(maximum > 0);
    assert_eq!(app.router.options_browser().detail_scroll, maximum);
    app.reduce_key(KeyEvent::new(KeyCode::PageUp, KeyModifiers::NONE));
    assert_eq!(
        app.router.options_browser().detail_scroll,
        maximum.saturating_sub(page)
    );
}

#[test]
fn options_long_error_is_readable_with_paging_and_plain_output_is_exhaustive() {
    let mut app = options_app("context:build", "sampleLimit", 40, 12);
    app.reduce_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    let error = "Invalid value. ".repeat(20) + "Final instruction preserved.";
    app.router
        .options_browser_mut()
        .edit
        .as_mut()
        .unwrap()
        .error = Some(error.clone());
    for _ in 0..100 {
        app.reduce_key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE));
    }
    let visible = draw(&app, 40, 12);
    assert!(
        visible.contains("Final instruction preserved."),
        "{visible}"
    );
    let plain = plain_options_lines(&app, 40, app.router.options()).join("\n");
    assert!(plain.contains(&error));
    assert!(plain.contains("Ctrl+G global"));
}
