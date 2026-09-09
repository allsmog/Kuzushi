use super::*;

fn render(app: &mut ShellApp, width: u16, height: u16) -> String {
    app.set_viewport(crate::TerminalViewport::new(width, height));
    let backend = ratatui::backend::TestBackend::new(width, height);
    let mut terminal = ratatui::Terminal::new(backend).unwrap();
    terminal
        .draw(|frame| crate::renderer::render_app(frame, app))
        .unwrap();
    terminal
        .backend()
        .buffer()
        .content
        .chunks(width as usize)
        .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
        .collect::<Vec<_>>()
        .join("\n")
}

fn press(app: &mut ShellApp, code: KeyCode) {
    let update = app.reduce_key(KeyEvent::new(code, KeyModifiers::NONE));
    assert!(update.handled && update.effects.is_empty());
}

fn range(text: &str) -> (usize, usize, usize) {
    let hint = text.lines().find(|line| line.contains(" / ")).unwrap();
    let hint = hint.trim_matches(|ch: char| ch == '│' || ch.is_whitespace());
    let (interval, remainder) = hint.split_once(" / ").unwrap();
    let (start, end) = interval.split_once('–').unwrap();
    let total = remainder.split_whitespace().next().unwrap();
    (
        start.parse().unwrap(),
        end.parse().unwrap(),
        total.parse().unwrap(),
    )
}

#[test]
fn quit_full_shell_keeps_a_readable_body_and_actions_at_40_by_12() {
    for origin in [None, Some(ShellView::Home)] {
        let mut app = app_with_disclosures();
        app.router.set_overlay_origin(origin);
        let first = render(&mut app, 40, 12);
        assert!(first.contains("CONFIRM SESSION EXIT"), "{first}");
        assert!(first.contains("y/Y exit"), "{first}");
        assert!(first.contains("n/N/Esc stay"), "{first}");
        let (start, end, _) = range(&first);
        assert!(start <= end, "{first}");
    }
}

#[test]
fn quit_full_shell_pages_without_skips_or_end_debt() {
    for (width, height) in [(40, 12), (80, 24), (120, 36)] {
        for origin in [None, Some(ShellView::Home)] {
            check_pages(width, height, origin);
        }
    }
}

#[test]
fn quit_resize_preserves_reading_and_cancel_restores_setup_and_draft() {
    let mut app = app_with_disclosures();
    app.router.set_overlay_origin(Some(ShellView::Setup));
    render(&mut app, 40, 12);
    press(&mut app, KeyCode::End);
    let narrow = range(&render(&mut app, 40, 12));
    assert_eq!(narrow.1, narrow.2);
    let wide = range(&render(&mut app, 120, 36));
    assert_eq!(wide.1, wide.2);
    press(&mut app, KeyCode::PageUp);
    assert!(range(&render(&mut app, 120, 36)).0 < wide.0);
    let narrow = render(&mut app, 40, 12);
    assert!(narrow.contains("y/Y exit") && narrow.contains("n/N/Esc stay"));
    press(&mut app, KeyCode::Esc);
    assert_eq!(app.shell_view(), ShellView::Setup);
    assert_eq!(app.input(), "unsaved shell draft");
}

#[test]
fn compact_quit_keeps_active_work_disclosure_and_exit_choices() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_running_tool_for_test("semgrep:scan");
    app.set_shell_view(ShellView::QuitConfirm);
    app.router.set_overlay_origin(Some(ShellView::Setup));
    let text = render(&mut app, 40, 12);
    assert!(text.contains("CONFIRM SESSION EXIT"), "{text}");
    assert!(text.contains("cancellation"), "{text}");
    assert!(text.contains("y/Y cancel if needed + exit"), "{text}");
    assert!(text.contains("n/N/Esc stay"), "{text}");
    press(&mut app, KeyCode::Esc);
    assert!(app.has_running_work());
}

#[test]
fn tiny_quit_frames_never_claim_an_inverted_reading_range() {
    for (width, height) in [(1, 1), (10, 3), (20, 6), (40, 8)] {
        let mut app = app_with_disclosures();
        app.router.set_overlay_origin(Some(ShellView::Setup));
        let text = render(&mut app, width, height);
        assert!(!text.contains("1–0"), "{text}");
        if height >= 6 {
            assert!(text.contains("y/Y exit"), "{text}");
            assert!(text.contains("n/N/Esc stay"), "{text}");
        }
    }
}

fn check_pages(width: u16, height: u16, origin: Option<ShellView>) {
    let mut app = app_with_disclosures();
    app.router.set_overlay_origin(origin);
    let mut text = render(&mut app, width, height);
    let mut covered = text.clone();
    let mut previous = range(&text);
    for _ in 0..100 {
        if previous.1 == previous.2 {
            break;
        }
        press(&mut app, KeyCode::PageDown);
        text = render(&mut app, width, height);
        let current = range(&text);
        assert!(
            current.0 <= previous.1 + 1,
            "skipped rows: {previous:?} -> {current:?}"
        );
        assert!(current.1 > previous.1, "paging did not advance: {text}");
        assert!(text.contains("y/Y exit") && text.contains("n/N/Esc stay"));
        covered.push_str(&text);
        previous = current;
    }
    assert_eq!(previous.1, previous.2);
    for n in 0..30 {
        assert!(
            covered.contains(&format!("draft {n} ·")),
            "missing draft {n}"
        );
    }
    check_end_and_restore(&mut app, width, height, previous.0);
}

fn check_end_and_restore(app: &mut ShellApp, width: u16, height: u16, last_start: usize) {
    for _ in 0..20 {
        press(app, KeyCode::PageDown);
    }
    press(app, KeyCode::PageUp);
    assert!(range(&render(app, width, height)).0 < last_start);
    press(app, KeyCode::Home);
    assert_eq!(range(&render(app, width, height)).0, 1);
    press(app, KeyCode::End);
    let last = range(&render(app, width, height));
    assert_eq!(last.1, last.2);
    press(app, KeyCode::Up);
    assert_eq!(range(&render(app, width, height)).0, last.0 - 1);
    press(app, KeyCode::Esc);
    assert_ne!(app.shell_view(), ShellView::QuitConfirm);
    assert_eq!(app.input(), "unsaved shell draft");
    assert_eq!(app.router.quit_confirm_scroll(), 0);
}
