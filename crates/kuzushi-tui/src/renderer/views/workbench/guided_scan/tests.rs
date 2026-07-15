use super::*;

#[test]
fn guided_question_keeps_room_for_the_cockpit() {
    let model = question_fixture();

    assert_eq!(guided_question_height(Rect::new(0, 0, 40, 8), &model), 5);
}

#[test]
fn guided_question_is_bounded_on_tall_terminals() {
    let mut model = question_fixture();
    model.options = (0..20).map(|_| option_fixture()).collect();

    assert_eq!(guided_question_height(Rect::new(0, 0, 120, 60), &model), 25);
}

#[test]
fn option_window_keeps_the_focused_row_visible() {
    let mut model = question_fixture();
    model.options = (0..10).map(|_| option_fixture()).collect();
    model.cursor = 8;

    assert_eq!(visible_option_range(&model, 3), (7, 10));
}

#[test]
fn accepted_other_value_is_confirmed_in_the_question_card() {
    let mut model = question_fixture();
    model.acknowledgement = Some("Accepted sample limit = 321".to_string());

    let rendered = guided_question_lines(&model, 80)
        .iter()
        .flat_map(|line| line.spans.iter())
        .map(|span| span.content.as_ref())
        .collect::<String>();

    assert!(rendered.contains("Accepted sample limit = 321"));
}

#[test]
fn other_editor_renders_the_cursor_and_multiline_paste_placeholder() {
    let mut model = question_fixture();
    model.other_open = true;
    model.other_draft = "⟪paste #1 · 2 lines · 12 chars⟫".to_string();
    model.other_cursor = model.other_draft.chars().count();

    let rendered = guided_question_lines(&model, 80)
        .iter()
        .flat_map(|line| line.spans.iter())
        .map(|span| span.content.as_ref())
        .collect::<String>();

    assert!(rendered.contains("paste #1 · 2 lines · 12 chars"));
    assert!(rendered.contains('▏'));
}

#[test]
fn long_other_editor_keeps_the_cursor_visible_at_compact_and_wide_widths() {
    let mut model = question_fixture();
    model.other_open = true;
    model.other_draft = "x".repeat(512);
    model.other_cursor = model.other_draft.chars().count();

    for width in [38, 118] {
        let rendered = other_editor_line(&model, width);
        assert!(rendered.contains('▏'), "cursor hidden at width {width}");
        assert!(
            crate::renderer::shared::text::display_width(&rendered) <= width,
            "editor overflowed width {width}: {rendered}"
        );
    }
}

#[test]
fn long_unicode_other_editor_is_column_safe_and_keeps_the_cursor_visible() {
    let mut model = question_fixture();
    model.other_open = true;
    model.other_draft = "界".repeat(512);
    model.other_cursor = model.other_draft.chars().count();

    for width in [38, 118] {
        let rendered = other_editor_line(&model, width);
        assert!(rendered.contains('▏'), "cursor hidden at width {width}");
        assert!(rendered.contains('界'));
        assert!(
            crate::renderer::shared::text::display_width(&rendered) <= width,
            "Unicode editor overflowed width {width}: {rendered}"
        );
    }
}

#[test]
fn focused_unicode_option_is_fitted_to_terminal_columns() {
    let option = crate::app::GuidedQuestionOption {
        label: "修正🔐e\u{301} very long choice".to_string(),
        description: "説明".to_string(),
        selected: true,
        recommended: true,
        other: false,
    };

    for width in [18, 24, 40] {
        let line = option_line(0, &option, true, true, width, theme::accent());
        let rendered = line
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<String>();
        assert_eq!(
            crate::renderer::shared::text::display_width(&rendered),
            width
        );
    }
}

fn other_editor_line(model: &GuidedScanQuestionModel, width: usize) -> String {
    guided_question_lines(model, width)
        .into_iter()
        .find(|line| {
            line.spans
                .iter()
                .any(|span| span.content.contains("Other ›"))
        })
        .expect("Other editor line")
        .spans
        .iter()
        .map(|span| span.content.as_ref())
        .collect()
}

fn question_fixture() -> GuidedScanQuestionModel {
    GuidedScanQuestionModel {
        header: "MAP · ROUTE".to_string(),
        prompt: "What should Kuzushi do?".to_string(),
        detail: "detail".to_string(),
        progress: Some("step 1 of 4".to_string()),
        options: Vec::new(),
        cursor: 0,
        multi_select: false,
        accept_remaining_defaults: false,
        other_open: false,
        other_draft: String::new(),
        other_cursor: 0,
        acknowledgement: None,
        error: None,
    }
}

fn option_fixture() -> crate::app::GuidedQuestionOption {
    crate::app::GuidedQuestionOption {
        label: "Run module".to_string(),
        description: "description".to_string(),
        selected: false,
        recommended: false,
        other: false,
    }
}
