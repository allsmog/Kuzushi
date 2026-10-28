use super::reading::screen;
use super::*;

#[test]
fn boundary_overview_keeps_workload_visible_before_long_explanations() {
    let (_root, mut app) = fixture();
    app.reduce_resize(80, 24);
    let state = app.router.scope_review_mut().as_mut().unwrap();
    let review = std::sync::Arc::make_mut(state.review.as_mut().unwrap());
    review.record.draft.scopes[0].rationale = format!(
        "{}Keep callback ownership explicit.",
        "A parent boundary explained this source relationship. ".repeat(24)
    );
    let before = app.scope_review().unwrap().review.clone();
    app.set_input("retained scope draft");
    app.set_cursor(7);
    for (width, height) in [(80, 24), (60, 20)] {
        app.reduce_resize(width, height);
        let overview = screen(&app, width, height);
        assert!(overview.contains("Next study"), "{overview}");
        assert!(!overview.contains("Source snapshot:"), "{overview}");
    }
    assert!(press(&mut app, KeyCode::Tab).effects.is_empty());
    let full = crate::renderer::render_plain_app(&app, 200);
    let full = full.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(full.contains("Keep callback ownership explicit."), "{full}");
    assert!(full.contains("Source snapshot:"), "{full}");
    press(&mut app, KeyCode::Esc);
    assert_eq!(app.scope_review().unwrap().review, before);
    assert_eq!((app.input(), app.cursor()), ("retained scope draft", 7));
}

#[test]
fn full_scope_document_preserves_literal_spaces_in_recorded_file_names() {
    let (root, mut app) = fixture();
    std::fs::write(
        root.path().join("auth/session  token.rs"),
        "// inert source
",
    )
    .unwrap();
    let update = press(&mut app, KeyCode::Char('c'));
    finish(&mut app, root.path(), update).unwrap();
    let update = press(&mut app, KeyCode::Char('f'));
    finish(&mut app, root.path(), update).unwrap();
    let text = crate::renderer::render_plain_app(&app, 200);
    assert!(text.contains("auth/session  token.rs"), "{text}");
}

#[test]
fn overview_keeps_coverage_visible_and_plain_output_complete_without_opening_reader() {
    let (_root, mut app) = fixture();
    app.reduce_resize(160, 48);
    let text = screen(&app, 160, 48);
    assert!(text.contains("Coverage:"), "{text}");
    assert!(text.contains("Without content identity:"), "{text}");
    assert!(
        text.contains("Next study calls and dollars: not estimated"),
        "{text}"
    );
    assert!(!text.contains("Scope id:"), "{text}");
    let plain = crate::renderer::render_plain_app(&app, 200);
    assert!(plain.contains("Scope id:"), "{plain}");
    assert!(plain.contains("Source snapshot:"), "{plain}");
    assert!(!app.scope_review().unwrap().detail_reader.open);
}

#[test]
fn shared_context_overview_discloses_that_its_files_do_not_add_discovery_jobs() {
    let (root, mut app) = fixture();
    split(&mut app, root.path());
    let update = app.apply_scope_menu(13);
    finish(&mut app, root.path(), update).unwrap();
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Down);
    let state = app.scope_review().unwrap();
    let text = crate::ui_view_models::scope_review::scope_display_lines(
        &app,
        state,
        &crate::ui_view_models::scope_review::scope_source_view(&app, state),
        200,
    )
    .join("\n");
    assert!(
        text.contains("shared context only; no discovery jobs"),
        "{text}"
    );
    assert!(text.contains("default passes = 6 jobs"), "{text}");
    assert!(!root.path().join(".kuzushi/v3/campaigns").exists());
}
