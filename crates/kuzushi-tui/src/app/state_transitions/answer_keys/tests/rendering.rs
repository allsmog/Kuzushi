use super::*;
use crate::ui_view_models::{answers_layout, answers_visible};
use ratatui::backend::TestBackend;
use ratatui::layout::Rect;
use ratatui::Terminal;

pub(super) fn render(app: &mut ShellApp, width: u16, height: u16) -> String {
    app.reduce_resize(width, height);
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal
        .draw(|frame| crate::renderer::render_app(frame, app))
        .unwrap();
    let buffer = terminal.backend().buffer();
    (0..height)
        .map(|y| {
            let row = (0..width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>();
            format!("{row}\n")
        })
        .collect()
}

#[test]
fn answers_render_complete_scrollable_responses_at_small_and_large_sizes() {
    let mut app = app();
    for (width, height) in [(40, 12), (80, 24), (120, 36), (160, 48)] {
        let screen = render(&mut app, width, height);
        assert!(screen.contains("ANSWERS"), "{width}×{height}\n{screen}");
        key(&mut app, KeyCode::Home, KeyModifiers::NONE);
        let first = render(&mut app, width, height);
        assert!(
            first.contains("Captured context"),
            "{width}×{height}\n{first}"
        );
        key(&mut app, KeyCode::End, KeyModifiers::NONE);
        let last = render(&mut app, width, height);
        assert!(last.contains("answer line 99"), "{width}×{height}\n{last}");
        let end = app.router.answers().scroll;
        key(&mut app, KeyCode::PageUp, KeyModifiers::NONE);
        assert!(app.router.answers().scroll < end);
        assert_eq!(app.input(), "unfinished shell command");
    }
}

#[test]
fn answers_context_revision_stays_visible_when_target_name_is_long() {
    let mut app = app();
    app.agent_chat_mut().unwrap().thread_context_key = Some(context(
        Path::new("/a-very-long-project-name-that-exceeds-the-answer-pane-width"),
        "0123456789abcdef",
    ));
    let screen = render(&mut app, 120, 36);
    assert!(screen.contains("Captured 0123456789ab"), "{screen}");
}

#[test]
fn answers_focus_switch_retains_wide_pane_and_collapses_narrow_pane() {
    let mut app = app();
    render(&mut app, 160, 48);
    key(&mut app, KeyCode::Char('t'), KeyModifiers::CONTROL);
    let wide = render(&mut app, 160, 48);
    assert!(answers_visible(&app));
    assert!(wide.contains("ANSWERS"));
    assert_eq!(app.router.answers().focus, AnswerFocus::Workspace);
    let area = crate::renderer::primary_body_area(&app, Rect::new(0, 0, 160, 48));
    let layout = answers_layout(&app, area);
    assert!(layout.workspace.width >= 96);
    assert!(layout.answers.unwrap().x >= layout.workspace.right());
    assert_eq!(
        crate::renderer::workbench_primary_area(&app, Rect::new(0, 0, 160, 48)),
        layout.workspace
    );
    let narrow = render(&mut app, 80, 24);
    assert!(narrow.contains("Ctrl+T read / reply"));
    key(&mut app, KeyCode::Char('t'), KeyModifiers::CONTROL);
    assert!(render(&mut app, 80, 24).contains("ANSWERS"));
    key(&mut app, KeyCode::Esc, KeyModifiers::NONE);
    assert!(!answers_visible(&app));
}

#[test]
fn answers_resize_keeps_reply_text_and_every_answer_line_reachable() {
    let mut app = app();
    app.reduce_paste("Multiline Unicode question αβ\nsecond line");
    for (width, height) in [(160, 48), (80, 24), (40, 12), (120, 36)] {
        let screen = render(&mut app, width, height);
        assert!(screen.contains("second line"), "{width}×{height}\n{screen}");
        assert_eq!(
            app.router.answers().draft.text(),
            "Multiline Unicode question αβ\nsecond line"
        );
        assert_eq!(app.router.answers().focus, AnswerFocus::Reply);
    }
    key(&mut app, KeyCode::Esc, KeyModifiers::NONE);
    for size in [(1, 1), (2, 2), (4, 5), (80, 24)] {
        render(&mut app, size.0, size.1);
    }
    key(&mut app, KeyCode::End, KeyModifiers::NONE);
    assert!(render(&mut app, 80, 24).contains("answer line 99"));
}

#[test]
fn answers_wheel_scroll_and_click_follow_rendered_pane_geometry() {
    let mut app = app();
    render(&mut app, 160, 48);
    let full = Rect::new(0, 0, 160, 48);
    let pane = answers_layout(&app, crate::renderer::primary_body_area(&app, full))
        .answers
        .unwrap();
    let mouse = |kind, column| MouseEvent {
        kind,
        column,
        row: pane.y + 3,
        modifiers: KeyModifiers::NONE,
    };
    app.reduce_mouse(mouse(MouseEventKind::ScrollDown, pane.x + 2));
    assert!(app.router.answers().scroll.unwrap() > 0);
    let scroll = app.router.answers().scroll;
    app.reduce_mouse(mouse(
        MouseEventKind::Down(crossterm::event::MouseButton::Left),
        1,
    ));
    assert_eq!(app.router.answers().focus, AnswerFocus::Workspace);
    app.reduce_mouse(mouse(
        MouseEventKind::Down(crossterm::event::MouseButton::Left),
        pane.x + 2,
    ));
    assert_eq!(app.router.answers().focus, AnswerFocus::Reading);
    assert_eq!(app.router.answers().scroll, scroll);
    assert_eq!(app.input(), "unfinished shell command");
}
