use super::*;

fn search(app: &mut ShellApp, query: &str) {
    press(app, KeyCode::Enter);
    press(app, KeyCode::Char('/'));
    for ch in query.chars() {
        let update = app.reduce_key(KeyEvent::new(KeyCode::Char(ch), KeyModifiers::NONE));
        assert!(update.handled && update.effects.is_empty());
    }
}

#[test]
fn coverage_path_action_opens_from_every_coverage_category_without_starting_work() {
    for branch in [
        ScopeBranch::Uncovered,
        ScopeBranch::Excluded,
        ScopeBranch::Overlap,
    ] {
        let (root, mut app) = fixture();
        let state = app.router.scope_review_mut().as_mut().unwrap();
        state.cursor = state
            .tree_rows()
            .iter()
            .position(|row| row == &ScopeTreeRow::Branch(branch.clone()))
            .unwrap();
        let before = state.review.clone();
        search(&mut app, "Exclude a file or directory");
        let detail = crate::renderer::render_plain_app(&app, 200);
        assert!(!detail.contains("Select a scope before using this action."));
        assert!(press(&mut app, KeyCode::Enter).effects.is_empty());
        let state = app.scope_review().unwrap();
        assert_eq!(
            state.form.as_ref().map(|form| form.kind),
            Some(ScopeEditKind::ExcludePath)
        );
        assert!(state.menu.is_none() && state.menu_search.is_none());
        assert_eq!(state.review, before);
        assert!(!root.path().join(".kuzushi/v3/campaigns").exists());
    }
}

#[test]
fn coverage_path_action_retains_invalid_literal_and_saved_scope_after_dispatch_failure() {
    let (root, mut app) = fixture();
    app.set_input("kept exclusion draft");
    app.set_cursor(5);
    let state = app.router.scope_review_mut().as_mut().unwrap();
    state.cursor = state
        .tree_rows()
        .iter()
        .position(|row| row == &ScopeTreeRow::Branch(ScopeBranch::Excluded))
        .unwrap();
    let before = state.review.clone();
    search(&mut app, "Exclude a file or directory");
    press(&mut app, KeyCode::Enter);
    assert!(app.scope_review().unwrap().form.is_some());
    fill_form(
        &mut app,
        &[" . ", "Invalid literal must remain distinct from root"],
    );
    let update = press(&mut app, KeyCode::F(2));
    let error = finish(&mut app, root.path(), update).unwrap_err();
    app.scope_review_failed("pack:scopes", &error.to_string());
    let state = app.scope_review().unwrap();
    assert_eq!(state.review, before);
    assert_eq!(state.form.as_ref().unwrap().fields[0].1.text(), " . ");
    assert!(state.notice.as_ref().unwrap().contains("Action stopped"));
    assert_eq!((app.input(), app.cursor()), ("kept exclusion draft", 5));
    assert!(!root.path().join(".kuzushi/v3/campaigns").exists());
}

#[test]
fn whole_repository_result_focuses_its_new_boundary_after_a_coverage_action() {
    let (root, mut app) = fixture();
    split(&mut app, root.path());
    app.set_input("kept whole-repository draft");
    app.set_cursor(8);
    let state = app.router.scope_review_mut().as_mut().unwrap();
    state.cursor = state
        .tree_rows()
        .iter()
        .position(|row| row == &ScopeTreeRow::Branch(ScopeBranch::Excluded))
        .unwrap();
    state.scroll = 12;
    let update = app.apply_scope_menu(7);
    finish(&mut app, root.path(), update).unwrap();
    let state = app.scope_review().unwrap();
    assert_eq!(selected_scope(state).unwrap().paths, ["."]);
    assert_eq!(state.scroll, 0);
    assert!(state.review.as_ref().unwrap().record.acceptance.is_none());
    assert_eq!(
        (app.input(), app.cursor()),
        ("kept whole-repository draft", 8)
    );
    assert!(!root.path().join(".kuzushi/v3/campaigns").exists());
}

#[test]
fn whole_repository_failure_keeps_the_coverage_origin_and_saved_boundaries() {
    let (root, mut app) = fixture();
    let state = app.router.scope_review_mut().as_mut().unwrap();
    state.cursor = state
        .tree_rows()
        .iter()
        .position(|row| row == &ScopeTreeRow::Branch(ScopeBranch::Excluded))
        .unwrap();
    let before = (state.review.clone(), state.selected_row());
    std::fs::write(
        root.path().join("README.md"),
        "Changed source after inventory.\n",
    )
    .unwrap();
    let update = app.apply_scope_menu(7);
    let error = finish(&mut app, root.path(), update).unwrap_err();
    app.scope_review_failed("pack:scopes", &error.to_string());
    let state = app.scope_review().unwrap();
    assert_eq!((state.review.clone(), state.selected_row()), before);
    assert!(state.pending.is_none());
    assert!(!root.path().join(".kuzushi/v3/campaigns").exists());
}

#[test]
fn filtered_selection_dispatches_the_original_action_and_preserves_the_composer() {
    let (root, mut app) = fixture();
    app.set_input("retained scope draft");
    app.set_cursor(4);
    let before = app.scope_review().unwrap().review.clone().unwrap();
    search(&mut app, "USE boundary shared");
    assert_eq!(app.scope_review().unwrap().menu, Some(13));
    assert_eq!(app.scope_review().unwrap().matching_actions(), [13]);
    let update = press(&mut app, KeyCode::Enter);
    finish(&mut app, root.path(), update).unwrap();
    let state = app.scope_review().unwrap();
    let after = state.review.as_ref().unwrap();
    assert!(after.record.draft.shared_scope.is_some());
    assert_eq!(after.record.draft.scopes, before.record.draft.scopes);
    assert!(!after.record.draft.shared_discovery);
    assert!(state.menu_search.is_none());
    assert_eq!((app.input(), app.cursor()), ("retained scope draft", 4));
    assert!(!root.path().join(".kuzushi/v3/campaigns").exists());
}

#[test]
fn unmatched_query_and_modified_enter_cannot_activate_a_hidden_action() {
    let (_root, mut app) = fixture();
    let before = app.scope_review().unwrap().review.clone();
    search(&mut app, "no such action");
    for code in [KeyCode::Down, KeyCode::Up, KeyCode::Enter] {
        assert!(press(&mut app, code).effects.is_empty());
    }
    assert!(app.scope_review().unwrap().form.is_none());
    assert_eq!(app.scope_review().unwrap().review, before);
    assert!(app
        .scope_review()
        .unwrap()
        .notice
        .as_ref()
        .unwrap()
        .contains("No matching actions"));
    app.reduce_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
    app.reduce_paste("Split scope");
    let update = app.reduce_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL));
    assert!(update.effects.is_empty());
    assert!(app.scope_review().unwrap().form.is_none());
}

#[test]
fn moving_through_filtered_results_uses_global_action_identities() {
    let (root, mut app) = fixture();
    let update = app.apply_scope_menu(13);
    finish(&mut app, root.path(), update).unwrap();
    search(&mut app, "shared");
    assert_eq!(app.scope_review().unwrap().matching_actions(), [6, 13, 14]);
    for expected in [13, 14, 14] {
        press(&mut app, KeyCode::Down);
        assert_eq!(app.scope_review().unwrap().menu, Some(expected));
    }
    let update = press(&mut app, KeyCode::Enter);
    finish(&mut app, root.path(), update).unwrap();
    assert!(app
        .scope_review()
        .unwrap()
        .review
        .as_ref()
        .unwrap()
        .record
        .draft
        .shared_scope
        .is_none());
}

#[test]
fn paste_and_editing_chords_belong_to_the_search_field() {
    let (_root, mut app) = fixture();
    app.set_input("unchanged composer");
    app.set_cursor(3);
    press(&mut app, KeyCode::Enter);
    app.reduce_paste("  shared\n\tcontext  ");
    assert_eq!(
        app.scope_review()
            .unwrap()
            .menu_search
            .as_ref()
            .unwrap()
            .text(),
        "shared context"
    );
    press(&mut app, KeyCode::Home);
    press(&mut app, KeyCode::Delete);
    press(&mut app, KeyCode::Char('s'));
    press(&mut app, KeyCode::End);
    app.reduce_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
    press(&mut app, KeyCode::Char('j'));
    press(&mut app, KeyCode::Char('k'));
    assert_eq!(
        app.scope_review()
            .unwrap()
            .menu_search
            .as_ref()
            .unwrap()
            .text(),
        "jk"
    );
    assert_eq!((app.input(), app.cursor()), ("unchanged composer", 3));
}

#[test]
fn escape_clears_search_then_closes_the_menu_without_losing_the_scope_cursor() {
    let (_root, mut app) = fixture();
    let cursor = app.scope_review().unwrap().cursor;
    search(&mut app, "shared context");
    press(&mut app, KeyCode::Esc);
    assert!(app.scope_review().unwrap().menu_search.is_none());
    assert_eq!(app.scope_review().unwrap().menu, Some(13));
    assert_eq!(
        app.scope_review().unwrap().matching_actions().len(),
        SCOPE_ACTIONS.len()
    );
    press(&mut app, KeyCode::Esc);
    assert!(app.scope_review().unwrap().open);
    assert!(app.scope_review().unwrap().menu.is_none());
    assert_eq!(app.scope_review().unwrap().cursor, cursor);
}

#[test]
fn refused_action_preserves_its_search_query_and_selection() {
    let (_root, mut app) = fixture();
    app.router.scope_review_mut().as_mut().unwrap().cursor = 1;
    search(&mut app, "Use boundary shared");
    let before = app.scope_review().unwrap().menu_search.clone();
    let update = press(&mut app, KeyCode::Enter);
    let state = app.scope_review().unwrap();
    assert!(update.effects.is_empty());
    assert_eq!(state.menu_search, before);
    assert_eq!(state.menu, Some(13));
    assert!(state
        .notice
        .as_deref()
        .unwrap()
        .contains("Select a primary boundary"));
}

#[test]
fn detail_paging_preserves_the_filtered_selection_and_plain_reader() {
    let (_root, mut app) = fixture();
    app.set_input("kept scope draft");
    search(&mut app, "shared context");
    app.reduce_resize(40, 12);
    let query = app.scope_review().unwrap().menu_search.clone();
    assert!(press(&mut app, KeyCode::PageDown).effects.is_empty());
    let state = app.scope_review().unwrap();
    assert!(state.scroll > 0);
    assert_eq!(state.menu, Some(13));
    assert_eq!(state.menu_search, query);
    assert_eq!(app.input(), "kept scope draft");
    let plain = crate::render_plain_app(&app, 40);
    assert!(!plain.contains('\x1b'));
    let words = plain.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(words.contains("Search: shared context"));
    assert!(words.contains("PgUp/Dn"));
    assert!(words.contains("Recorded Git SHA"));
    press(&mut app, KeyCode::PageUp);
    assert_eq!(app.scope_review().unwrap().scroll, 0);
}

#[test]
fn search_and_empty_results_are_visible_at_every_viewport() {
    let (_root, mut app) = fixture();
    search(&mut app, "shared context");
    for size in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.reduce_resize(size.0, size.1);
        assert_screen(
            &app,
            size,
            &[
                "Search: shared context",
                "shared context",
                "Esc clear search",
            ],
        );
    }
    app.reduce_paste(" é未確認 ");
    assert!(app.scope_review().unwrap().matching_actions().is_empty());
    for size in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.reduce_resize(size.0, size.1);
        assert_screen(&app, size, &["No matching actions", "Esc clear search"]);
    }
}

fn assert_screen(app: &ShellApp, size: (u16, u16), expected: &[&str]) {
    let mut terminal = Terminal::new(TestBackend::new(size.0, size.1)).unwrap();
    terminal
        .draw(|frame| crate::render_app(frame, app))
        .unwrap();
    let screen = format!("{:?}", terminal.backend().buffer());
    assert_source_status(app, terminal.backend().buffer(), size);
    for text in expected {
        assert!(screen.contains(text), "{size:?}: missing {text}: {screen}");
    }
}

fn assert_source_status(app: &ShellApp, buffer: &ratatui::buffer::Buffer, size: (u16, u16)) {
    use crate::ui_view_models::{scope_review::scope_source_view, study_config::study_config_area};
    let area = study_config_area(size.0, size.1);
    let text: String = (area.x + 2..area.right() - 2)
        .map(|x| buffer.cell((x, area.y + 2)).unwrap().symbol())
        .collect();
    let source = scope_source_view(app, app.scope_review().unwrap());
    let label =
        crate::renderer::shared::text::fit(source.label(), area.width.saturating_sub(4) as usize);
    assert_eq!(text.trim_end(), label.trim_end());
}
