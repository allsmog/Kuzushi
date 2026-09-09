use super::*;

fn render(app: &mut ShellApp, width: u16, height: u16) -> (String, bool) {
    app.set_viewport(crate::TerminalViewport::new(width, height));
    let backend = ratatui::backend::TestBackend::new(width, height);
    let mut terminal = ratatui::Terminal::new(backend).unwrap();
    terminal
        .draw(|frame| crate::renderer::render_app(frame, app))
        .unwrap();
    let buffer = terminal.backend().buffer();
    let cursor = buffer
        .content
        .iter()
        .any(|cell| cell.modifier.contains(ratatui::style::Modifier::REVERSED));
    let text = buffer
        .content
        .chunks(width as usize)
        .map(visible_row_text)
        .collect::<Vec<_>>()
        .join("\n");
    (text, cursor)
}

fn visible_row_text(row: &[ratatui::buffer::Cell]) -> String {
    use unicode_width::UnicodeWidthStr;
    let mut text = String::new();
    let mut column = 0;
    while let Some(cell) = row.get(column) {
        text.push_str(cell.symbol());
        column += cell.symbol().width().max(1);
    }
    text
}

#[test]
fn planning_option_field_cursor_and_actions_stay_visible_at_supported_sizes() {
    for setup in [false, true] {
        for (width, height) in [(40, 12), (80, 24), (120, 36)] {
            let value = format!("{}\nTAIL東京", "long draft ".repeat(60));
            let mut app = editor("sampleLimit", &value, setup);
            let (text, cursor) = render(&mut app, width, height);
            assert!(text.contains("EDITING OPTION"), "{text}");
            assert!(text.contains("TAIL東京") && cursor, "{text}");
            assert!(
                text.contains("Enter save") && text.contains("Esc cancel"),
                "{text}"
            );
            assert!(!text.contains("type a command"), "{text}");
            press(&mut app, KeyCode::Home, KeyModifiers::CONTROL);
            let (text, cursor) = render(&mut app, width, height);
            assert!(text.contains("long draft long draft") && cursor, "{text}");
            assert_eq!(draft(&app), value);
        }
    }
}

#[test]
fn long_planning_option_validation_remains_readable_without_losing_the_draft() {
    let mut app = editor("sampleLimit", "invalid", true);
    let error = (0..20)
        .map(|n| format!("DETAIL{n:02}: complete validation explanation"))
        .collect::<Vec<_>>()
        .join("\n");
    app.engagement.planning_picker_mut().set_option_error(error);
    let (mut text, _) = render(&mut app, 40, 12);
    assert!(text.contains("invalid"), "{text}");
    let mut read = text.clone();
    for _ in 0..100 {
        press(&mut app, KeyCode::PageDown, KeyModifiers::NONE);
        text = render(&mut app, 40, 12).0;
        assert!(
            text.contains("invalid") && text.contains("Enter save") && text.contains("Esc cancel"),
            "{text}"
        );
        read.push_str(&text);
    }
    for n in 0..20 {
        assert!(
            read.contains(&format!("DETAIL{n:02}")),
            "validation line {n} is unreachable"
        );
    }
    press(&mut app, KeyCode::PageUp, KeyModifiers::NONE);
    assert_ne!(render(&mut app, 40, 12).0, text);
    assert_eq!(draft(&app), "invalid");
    assert_eq!(
        app.planning_override_count(PlanningTaskId::GatherRepoContext),
        0
    );
}
