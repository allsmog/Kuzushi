use super::*;

pub(super) fn screen(app: &ShellApp, width: u16, height: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal
        .draw(|frame| crate::render_app(frame, app))
        .unwrap();
    terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect()
}

#[test]
fn tab_opens_scope_details_without_losing_tree_selection_or_composer() {
    let (root, mut app) = fixture();
    split(&mut app, root.path());
    press(&mut app, KeyCode::Down);
    app.set_input("kept operator text");
    app.set_cursor(4);
    let before = app.scope_review().unwrap().clone();
    assert!(press(&mut app, KeyCode::Tab).effects.is_empty());
    assert!(screen(&app, 80, 24).contains("SCOPE DETAIL"));
    for key in [
        KeyCode::Enter,
        KeyCode::Char('a'),
        KeyCode::Char('p'),
        KeyCode::Char('c'),
        KeyCode::Char(' '),
    ] {
        assert!(press(&mut app, key).effects.is_empty());
    }
    press(&mut app, KeyCode::Esc);
    let after = app.scope_review().unwrap();
    assert!(after.open && after.menu.is_none() && !after.accepting);
    assert_eq!(after.review, before.review);
    assert_eq!(after.cursor, before.cursor);
    assert_eq!(after.study_scope_ids, before.study_scope_ids);
    assert_eq!((app.input(), app.cursor()), ("kept operator text", 4));
}

#[test]
fn boundary_rationale_and_workload_precede_full_source_identifiers() {
    let (_root, app) = fixture();
    let text =
        crate::ui_view_models::scope_review::scope_detail(app.scope_review().unwrap(), Vec::new())
            .join("\n");
    let why = text.find("Why:").unwrap();
    assert!(why < text.find("All discovery boundaries:").unwrap());
    assert!(why < text.find("Scope id:").unwrap());
    assert!(text.find("Next study").unwrap() < text.find("Source snapshot:").unwrap());
}

#[test]
fn reader_has_six_content_rows_at_smallest_viewport_and_preserves_both_scrolls() {
    let (_root, mut app) = fixture();
    app.router.scope_review_mut().as_mut().unwrap().scroll = 3;
    press(&mut app, KeyCode::Tab);
    for (width, height) in [(160, 48), (120, 36), (96, 89), (80, 24), (60, 20), (40, 12)] {
        app.reduce_resize(width, height);
        let state = app.scope_review().unwrap();
        let area = crate::ui_view_models::study_config::study_config_area(width, height);
        let layout = crate::ui_view_models::scope_review::scope_review_layout(area, state);
        assert_eq!(layout.list.height, 0);
        assert_eq!(layout.detail.height, height - 6);
        let text = screen(&app, width, height);
        assert!(
            text.contains("SCOPE DETAIL") && text.contains("Tab / Esc tree"),
            "{width}x{height}: {text}"
        );
        assert_eq!(state.scroll, 3);
        let title = crate::ui_view_models::scope_review::scope_title(
            state,
            &crate::ui_view_models::scope_review::scope_source_view(&app, state),
        );
        assert_eq!(title, "SCOPE DETAIL · DRAFT r1");
        assert!(title.chars().count() < 36);
    }
    press(&mut app, KeyCode::PageDown);
    assert_eq!(app.scope_review().unwrap().detail_reader.scroll, 6);
    press(&mut app, KeyCode::Tab);
    assert_eq!(app.scope_review().unwrap().scroll, 3);
    press(&mut app, KeyCode::Tab);
    assert_eq!(app.scope_review().unwrap().detail_reader.scroll, 6);
    press(&mut app, KeyCode::Home);
    assert_eq!(app.scope_review().unwrap().detail_reader.scroll, 0);
    press(&mut app, KeyCode::End);
    assert!(screen(&app, 40, 12).contains("model requests."));
    let plain = crate::renderer::render_plain_app(&app, 80);
    assert!(plain.contains("Source snapshot:") && plain.contains("Last observed Git SHA:"));
    assert!(plain.contains("Recorded boundary approval: not accepted"));
    let compact = plain.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(compact.contains("In the tree, Space marks discovery boundaries"));
}

#[test]
fn reader_navigation_is_local_and_form_tab_keeps_its_field_ownership() {
    let (_root, mut app) = fixture();
    app.reduce_resize(40, 12);
    let initial = app.scope_review().unwrap().clone();
    press(&mut app, KeyCode::Tab);
    for code in [
        KeyCode::Down,
        KeyCode::Down,
        KeyCode::Up,
        KeyCode::Char('j'),
        KeyCode::Char('k'),
    ] {
        assert!(press(&mut app, code).effects.is_empty());
    }
    let state = app.scope_review().unwrap();
    assert_eq!(state.detail_reader.scroll, 1);
    assert_eq!(state.cursor, initial.cursor);
    assert_eq!(state.tree, initial.tree);
    press(&mut app, KeyCode::Esc);
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Enter);
    let before = app.scope_review().unwrap().form.clone().unwrap();
    press(&mut app, KeyCode::Tab);
    assert!(!app.scope_review().unwrap().detail_reader.open);
    assert_eq!(
        app.scope_review().unwrap().form.as_ref().unwrap().fields,
        before.fields
    );
}

#[test]
fn same_receipt_preserves_reader_but_different_proposals_restore_tree() {
    let (_root, mut app) = fixture();
    app.reduce_resize(40, 12);
    press(&mut app, KeyCode::Tab);
    press(&mut app, KeyCode::Down);
    let state = app.router.scope_review_mut().as_mut().unwrap();
    let review = state.review.as_deref().unwrap().clone();
    state.install(review.clone());
    assert!(state.detail_reader.open);
    assert_eq!(state.detail_reader.scroll, 1);
    let mut next_revision = review.clone();
    next_revision.reference.revision += 1;
    state.install(next_revision);
    assert!(state.detail_reader.open);
    assert_eq!(state.detail_reader.scroll, 0);
    let mut different = review;
    different.reference.proposal_id.push_str("-different");
    state.install(different);
    assert!(!state.detail_reader.open);
}

#[test]
fn model_and_context_receipts_remain_complete_after_boundary_and_workload() {
    let (_root, mut app) = fixture();
    let state = app.router.scope_review_mut().as_mut().unwrap();
    let review = std::sync::Arc::make_mut(state.review.as_mut().unwrap());
    let context = json!({"modelId":"saved-proposal-model","revisionId":"saved-proposal-revision","sha256":"full-proposal-context-digest"});
    review.record.generation = Some(serde_json::from_value(json!({
        "schemaVersion":1,"model":"openai-codex:gpt-5.5","runId":"recorded-proposal-run",
        "promptSha256":"prompt-digest","draftSha256":"draft-digest","contextRef":context,
        "inputBytes":4096,"suppliedFiles":1,"inventoriedFiles":2,"limitations":["Some names were omitted"]
    })).unwrap());
    let state = app.scope_review().unwrap();
    let lines = crate::ui_view_models::scope_review::scope_detail_lines(
        &app,
        state,
        &crate::ui_view_models::scope_review::scope_source_view(&app, state),
        120,
    )
    .join("\n");
    assert!(lines.find("Why:").unwrap() < lines.find("Next study").unwrap());
    assert!(
        lines.find("Next study").unwrap() < lines.find("Scan context: no matching study").unwrap()
    );
    assert!(lines.find("Next study").unwrap() < lines.find("saved-proposal-revision").unwrap());
    for exact in [
        "saved-proposal-model",
        "saved-proposal-revision",
        "full-proposal-context-digest",
        "recorded-proposal-run",
        "Some names were omitted",
        "Source snapshot:",
    ] {
        assert!(lines.contains(exact), "Missing {exact}");
    }
    app.reduce_resize(120, 36);
    let visible = screen(&app, 120, 36);
    assert!(
        visible.contains("Boundary:") && visible.contains("Why:") && visible.contains("Next study")
    );
}
