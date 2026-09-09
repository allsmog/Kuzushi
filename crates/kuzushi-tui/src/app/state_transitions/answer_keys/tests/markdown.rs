use super::*;

const RESPONSE: &str = "## Boundary review\n\n**Unverified** evidence and `check()` need review.\n\n7. Inspect source\n8. Verify behavior\n\n```rust\nfn check() {\n    if ready {\n        inspect();\n    }\n}\n```\n\n| Check | Evidence |\n| --- | --- |\n| Permission | No proof yet |\n| Scope | Selected target only |\n\n[Source](https://example.test/review/source.rs#L42)\n";

#[test]
fn answers_render_markdown_hierarchy_without_losing_code_or_links() {
    let mut app = app();
    app.agent_chat_mut().unwrap().answer = Some(RESPONSE.into());
    let screen = rendering::render(&mut app, 80, 48);
    key(&mut app, KeyCode::Home, KeyModifiers::NONE);
    let mut seen = screen;
    for _ in 0..12 {
        seen.push_str(&rendering::render(&mut app, 80, 48));
        key(&mut app, KeyCode::PageDown, KeyModifiers::NONE);
    }
    assert!(!seen.contains("## Boundary review"), "{seen}");
    assert!(!seen.contains("**Unverified**"), "{seen}");
    assert!(
        seen.contains("        inspect();"),
        "code indentation was lost: {seen}"
    );
    assert!(
        seen.contains("https://example.test/review/source.rs#L42"),
        "{seen}"
    );
    assert_eq!(app.agent_chat().unwrap().answer.as_deref(), Some(RESPONSE));
}

#[test]
fn narrow_answer_tables_keep_each_value_with_its_header() {
    let mut app = app();
    app.agent_chat_mut().unwrap().answer = Some("| Check | Evidence | Status |\n| --- | --- | --- |\n| Permission | Source not verified | Open |".into());
    let doc = answer_document(&app, 18);
    let text = doc
        .lines
        .iter()
        .map(|line| line.content.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(text.contains("Check:"), "{text}");
    assert!(text.contains("Evidence:"), "{text}");
    assert!(text.contains("Status: Open"), "{text}");
    assert!(!text.contains("| ---"), "{text}");
}

#[test]
fn answer_markdown_styles_reach_the_frame_and_plain_output_keeps_evidence() {
    use ratatui::{backend::TestBackend, style::Modifier, Terminal};
    let mut app = app();
    let chat = app.agent_chat_mut().unwrap();
    chat.question = "**Literal question**".into();
    chat.answer = Some(RESPONSE.into());
    app.reduce_resize(80, 60);
    let mut terminal = Terminal::new(TestBackend::new(80, 60)).unwrap();
    terminal
        .draw(|frame| crate::renderer::render_app(frame, &app))
        .unwrap();
    let buffer = terminal.backend().buffer();
    let (row, column) = (0..60)
        .find_map(|y| {
            let text: String = (0..80).map(|x| buffer[(x, y)].symbol()).collect();
            text.find("Boundary review").map(|x| (y, x as u16))
        })
        .expect("heading must be visible in the rendered answer");
    assert!(buffer[(column, row)]
        .modifier
        .contains(Modifier::BOLD | Modifier::UNDERLINED));
    let plain = crate::renderer::answer_plain_lines(&app, 76).join("\n");
    assert!(plain.contains("**Literal question**"));
    assert!(plain.contains("        inspect();"));
    assert!(plain.contains("https://example.test/review/source.rs#L42"));
    assert!(!plain.contains("## Boundary review"));
}

#[test]
fn compact_answer_reading_reserves_five_rows_and_keeps_return_controls() {
    let mut app = app();
    let screen = rendering::render(&mut app, 40, 12);
    let full = ratatui::layout::Rect::new(0, 0, 40, 12);
    let body = crate::renderer::primary_body_area(&app, full);
    let pane = crate::ui_view_models::answers_layout(&app, body)
        .answers
        .unwrap();
    assert!(
        crate::renderer::answer_body_area(pane).height >= 5,
        "{screen}"
    );
    assert!(
        screen.contains("Enter reply") && screen.contains("Ctrl+T workspace"),
        "{screen}"
    );
    let hidden_height = crate::ui_view_models::keybind_footer_chrome_height(&app, 12, 40);
    assert_eq!(hidden_height, 0);
    key(&mut app, KeyCode::Char('t'), KeyModifiers::CONTROL);
    assert_eq!(
        crate::ui_view_models::keybind_footer_chrome_height(&app, 12, 40),
        3
    );
}
