use super::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use kuzushi_core::{runtime::RuntimeCostReport, V2Config};

fn halted_cost_reader() -> ShellApp {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.session_mut().set_session_budget_usd(Some(1.0));
    app.record_cost_report(RuntimeCostReport::INCOMPLETE_ZERO);
    app.reduce_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    app.set_shell_view(ShellView::Cost);
    app.set_input("held operator draft");
    app.set_input_mode(crate::InputMode::Navigate);
    app
}

fn compact_text(lines: Vec<Line<'static>>) -> String {
    lines
        .into_iter()
        .flat_map(|line| line.spans)
        .flat_map(|span| span.content.chars().collect::<Vec<_>>())
        .filter(|character| !character.is_whitespace())
        .collect()
}

#[test]
fn paged_cost_reader_reaches_all_accounting_details_without_skipping_small_viewports() {
    for (width, height) in [(120, 36), (160, 48), (96, 89), (80, 24), (60, 20), (40, 12)] {
        let mut app = halted_cost_reader();
        app.set_viewport(crate::TerminalViewport::new(width, height));
        let area = cost_reader_area(&app).unwrap();
        let mut visited = String::new();
        let max = cost_max_scroll(&app).unwrap();
        loop {
            visited.push_str(&compact_text(shell_view_lines(&app, area)));
            let before = app.router.default_scroll().offset();
            app.reduce_key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE));
            let after = app.router.default_scroll().offset();
            assert!(usize::from(after - before) <= usize::from(area.height).max(1));
            if after == before {
                assert_eq!(after, max);
                break;
            }
        }
        assert!(
            visited.contains("unknown(meteringincomplete)/cap$1.00·unknown"),
            "{width}x{height}: {visited}"
        );
        assert!(
            visited.contains("Missingcosttelemetrystaysunknown."),
            "{visited}"
        );
        assert!(!visited.contains("100%"), "{visited}");
        assert_eq!(app.input(), "held operator draft");
        assert!(app.is_budget_halted());
        assert_eq!(app.session().session_budget_usd(), Some(1.0));
    }
}

#[test]
fn cost_reader_clamps_after_resize_and_pages_back_immediately() {
    let mut app = halted_cost_reader();
    app.set_viewport(crate::TerminalViewport::new(40, 12));
    app.router.default_scroll_mut().tail();
    app.set_viewport(crate::TerminalViewport::new(60, 20));
    let max = cost_max_scroll(&app).unwrap();
    let rows = cost_page_rows(&app).unwrap();
    app.reduce_key(KeyEvent::new(KeyCode::PageUp, KeyModifiers::NONE));
    assert_eq!(
        usize::from(app.router.default_scroll().offset()),
        usize::from(max).saturating_sub(rows)
    );
    assert!(crate::ui_view_models::footer_keybindings(&app)
        .iter()
        .any(|binding| binding.key == "PgUp/PgDn"));
    app.set_shell_view(ShellView::Setup);
    assert_eq!(cost_page_rows(&app), None);
    assert_eq!(cost_max_scroll(&app), None);
}

#[test]
fn cost_details_wrap_the_complete_uncertainty_label_at_each_width() {
    let app = halted_cost_reader();
    for width in [160, 120, 96, 80, 60, 40] {
        let lines = cost_lines(&app, Rect::new(0, 0, width, 100));
        assert!(lines.iter().all(|line| line.width() <= usize::from(width)));
        let text = compact_text(lines);
        assert!(text.contains("thissessionunknown(meteringincomplete)"));
        assert!(text.contains("lasttoolunknown(meteringincomplete)"));
    }
}

#[test]
fn compact_cost_footer_keeps_paging_visible_in_prompt_and_navigation_modes() {
    use ratatui::{backend::TestBackend, Terminal};
    for mode in [crate::InputMode::Prompt, crate::InputMode::Navigate] {
        let mut app = halted_cost_reader();
        app.set_input("");
        app.set_input_mode(mode);
        app.set_viewport(crate::TerminalViewport::new(40, 12));
        let mut terminal = Terminal::new(TestBackend::new(40, 12)).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let buffer = terminal.backend().buffer();
        let text = (0..12)
            .map(|y| (0..40).map(|x| buffer[(x, y)].symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("PgUp/PgDn"), "{mode:?}: {text}");
        assert!(text.contains("Spending stays halted"), "{text}");
    }
}
