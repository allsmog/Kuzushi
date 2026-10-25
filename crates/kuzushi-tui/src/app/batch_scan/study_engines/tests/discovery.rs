use super::*;
use crate::ui_view_models::study_engines::{engine_layout, engine_rows};
use ratatui::buffer::Buffer;

fn rendered(app: &ShellApp, width: u16, height: u16) -> Buffer {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal
        .draw(|frame| crate::renderer::render_app(frame, app))
        .unwrap();
    terminal.backend().buffer().clone()
}

fn list_rail(buffer: &Buffer, app: &ShellApp, width: u16, height: u16) -> String {
    let area = engine_layout(width, height, engine_rows(app).len()).list;
    (area.y..area.bottom())
        .map(|y| buffer[(area.right() - 1, y)].symbol())
        .collect()
}

#[test]
fn compact_continuation_marks_only_rows_that_exist_above_or_below() {
    let (_root, mut app) = fixture(false);
    focus(&mut app, "codeql");
    let top = list_rail(&rendered(&app, 40, 12), &app, 40, 12);
    assert_eq!(top.chars().next(), Some(' '));
    assert_eq!(top.chars().last(), Some('↓'));
    focus(&mut app, "agentic");
    let middle = list_rail(&rendered(&app, 40, 12), &app, 40, 12);
    assert_eq!(middle.chars().next(), Some('↑'));
    assert_eq!(middle.chars().last(), Some('↓'));
    focus(&mut app, "systems-hunt");
    let bottom = list_rail(&rendered(&app, 40, 12), &app, 40, 12);
    assert_eq!(bottom.chars().next(), Some('↑'));
    assert_eq!(bottom.chars().last(), Some(' '));
}

#[test]
fn resizing_to_tall_layout_keeps_selection_and_shows_all_choices_without_a_scrollbar() {
    let (_root, mut app) = fixture(false);
    focus(&mut app, "systems-hunt");
    let picker = app.study_engine_picker().unwrap().clone();
    let buffer = rendered(&app, 96, 89);
    let text = buffer
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>();
    for label in [
        "Automatic selection",
        "[Labs] codeql",
        "[Labs] taint-iris ·",
        "[Labs] taint-iris-next",
        "systems-hunt · model required",
    ] {
        assert!(text.contains(label), "{label}");
    }
    let rail = list_rail(&buffer, &app, 96, 89);
    assert!(!rail.contains(['↑', '↓', '█', '│']));
    assert_eq!(app.study_engine_picker().unwrap(), &picker);
    assert!(engine_layout(96, 89, engine_rows(&app).len()).detail.height >= 60);
}

#[test]
fn saved_unknown_choices_remain_reachable_and_can_be_removed_from_the_bottom() {
    let (_root, mut app) = fixture(false);
    let picker = app
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .engine_picker
        .as_mut()
        .unwrap();
    picker.automatic = false;
    picker.selected.insert("saved-retired-engine".into());
    picker.order.push("saved-retired-engine".into());
    focus(&mut app, "saved-retired-engine");
    let buffer = rendered(&app, 40, 12);
    let text = buffer
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>();
    assert!(text.contains("saved-retired-engine"));
    assert_eq!(list_rail(&buffer, &app, 40, 12).chars().next(), Some('↑'));
    assert!(app
        .handle_study_engine_key(KeyCode::Enter)
        .effects
        .is_empty());
    assert!(!app
        .study_engine_picker()
        .unwrap()
        .selected
        .contains("saved-retired-engine"));
}
