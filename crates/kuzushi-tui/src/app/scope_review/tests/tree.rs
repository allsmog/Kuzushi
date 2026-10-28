use super::*;

#[test]
fn tree_navigation_keeps_boundary_actions_on_the_selected_boundary() {
    let (root, mut app) = fixture();
    split(&mut app, root.path());
    app.open_scope_acceptance();
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::End);
    let accepted = press(&mut app, KeyCode::Enter);
    finish(&mut app, root.path(), accepted).unwrap();
    let original = selected_scope(app.scope_review().unwrap())
        .unwrap()
        .id
        .clone();
    assert!(press(&mut app, KeyCode::Right).effects.is_empty());
    press(&mut app, KeyCode::Down);
    assert_eq!(
        app.scope_review().unwrap().selected_file().as_deref(),
        Some("auth/login.rs")
    );
    assert!(app.scope_review().unwrap().selected_id().is_none());
    let update = press(&mut app, KeyCode::Char(' '));
    assert!(update.effects.is_empty());
    assert!(app.scope_review().unwrap().study_scope_ids.is_empty());
    press(&mut app, KeyCode::Left);
    assert_eq!(
        app.scope_review().unwrap().selected_id(),
        Some(original.as_str())
    );
    press(&mut app, KeyCode::Left);
    press(&mut app, KeyCode::Down);
    assert_ne!(
        app.scope_review().unwrap().selected_id(),
        Some(original.as_str())
    );
    assert!(!root.path().join(".kuzushi/v3/campaigns").exists());
}

#[test]
fn tree_file_exclusion_and_restore_prefill_exact_membership() {
    let (root, mut app) = super::literal_paths::literal_fixture();
    press(&mut app, KeyCode::Right);
    press(&mut app, KeyCode::Down);
    assert_eq!(
        app.scope_review().unwrap().selected_file().as_deref(),
        Some(" auth /owned.rs")
    );
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.scope_review().unwrap().menu, Some(4));
    press(&mut app, KeyCode::Enter);
    assert_eq!(
        app.scope_review().unwrap().form.as_ref().unwrap().fields[0]
            .1
            .text(),
        " auth /owned.rs"
    );
    app.router
        .scope_review_mut()
        .as_mut()
        .unwrap()
        .form
        .as_mut()
        .unwrap()
        .fields[1]
        .1 = FieldEditor::new("Defer exact member");
    let update = press(&mut app, KeyCode::F(2));
    finish(&mut app, root.path(), update).unwrap();
    let review = app.scope_review().unwrap().review.as_ref().unwrap();
    assert_eq!(review.coverage.excluded_files.files, [" auth /owned.rs"]);
    assert!(review.coverage.discovery_members["repository"]
        .files
        .contains(&"auth/login.rs".into()));
    select_branch(&mut app, ScopeBranch::Excluded);
    press(&mut app, KeyCode::Right);
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.scope_review().unwrap().menu, Some(11));
    press(&mut app, KeyCode::Enter);
    assert_eq!(
        app.scope_review().unwrap().form.as_ref().unwrap().fields[0]
            .1
            .text(),
        " auth /owned.rs"
    );
    let update = press(&mut app, KeyCode::Enter);
    finish(&mut app, root.path(), update).unwrap();
    assert_eq!(
        app.scope_review()
            .unwrap()
            .review
            .as_ref()
            .unwrap()
            .coverage
            .excluded_files
            .total,
        0
    );
}

#[test]
fn tree_pages_reach_members_beyond_the_preview_without_new_work() {
    let (root, mut app) = fixture();
    for index in 0..140 {
        std::fs::write(
            root.path().join(format!("member-{index:03}.rs")),
            "// Owned text\n",
        )
        .unwrap();
    }
    let update = press(&mut app, KeyCode::Char('c'));
    finish(&mut app, root.path(), update).unwrap();
    press(&mut app, KeyCode::Right);
    for offset in [32, 64, 96, 128] {
        select_row(
            &mut app,
            |row| matches!(row, ScopeTreeRow::Page { offset: next, .. } if *next == offset),
        );
        let update = press(&mut app, KeyCode::Enter);
        finish(&mut app, root.path(), update).unwrap();
        let state = app.scope_review().unwrap();
        assert!(state.files.is_none());
        assert!(state.row_count() <= 38);
        assert_eq!(
            state.tree.pages[&ScopeBranch::Scope("repository".into())].offset,
            offset
        );
    }
    assert!(app
        .scope_review()
        .unwrap()
        .tree_rows()
        .iter()
        .any(|row| matches!(row, ScopeTreeRow::File { path, .. } if path == "member-139.rs")));
    let selected = app.scope_review().unwrap().selected_row();
    let update = app.refresh_scope_head();
    finish(&mut app, root.path(), update).unwrap();
    assert_eq!(app.scope_review().unwrap().selected_row(), selected);
    assert!(!root.path().join(".kuzushi/v3/campaigns").exists());
}

#[test]
fn tree_revisions_clear_stale_pages_without_retargeting_a_removed_file() {
    let (root, mut app) = fixture();
    press(&mut app, KeyCode::Right);
    press(&mut app, KeyCode::Down);
    let file = app.scope_review().unwrap().selected_file().unwrap();
    let update = app.send_scope_edit(kuzushi_core::workspace::ScanScopeEdit::ExcludePath {
        path: file,
        reason: "Owned exclusion".into(),
    });
    finish(&mut app, root.path(), update).unwrap();
    assert_eq!(
        app.scope_review().unwrap().selected_id(),
        Some("repository")
    );
    assert!(app.scope_review().unwrap().selected_file().is_none());
    assert!(app.scope_review().unwrap().tree.pages.is_empty());
}

#[test]
fn scope_tree_context_uses_only_the_exact_target_and_proposal() {
    use kuzushi_core::capabilities::campaign::{ScopeStudyCaseInput, ScopeStudyDraft};
    let (root, mut app) = fixture();
    app.set_target(Some(std::fs::canonicalize(root.path()).unwrap()));
    let effects = app.open_scope_review();
    if !effects.is_empty() {
        finish(
            &mut app,
            root.path(),
            InputUpdate::handled_with_effects(effects),
        )
        .unwrap();
    }
    let reference = app
        .scope_review()
        .unwrap()
        .review
        .as_ref()
        .unwrap()
        .reference
        .clone();
    app.open_batch_scan_config(None);
    let config = app
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap();
    config.study.scope_draft = Some(ScopeStudyDraft {
        proposal_ref: reference,
        cases: vec![ScopeStudyCaseInput {
            scope_id: "repository".into(),
            passes: 3,
            threat_model_ref: None,
        }],
    });
    config.study.scan_input =
        Some(json!({"threatModelRef":{"revisionId":"common","sha256":"common-digest"}}));
    let effects = app.open_scope_review();
    if !effects.is_empty() {
        finish(
            &mut app,
            root.path(),
            InputUpdate::handled_with_effects(effects),
        )
        .unwrap();
    }
    assert!(
        details(&app).contains("inherits common"),
        "{}",
        details(&app)
    );
    assert!(details(&app).contains("common-digest"));
    for (binding, expected) in [
        (Some(Value::Null), "explicitly omitted"),
        (
            Some(json!({"revisionId":"local","sha256":"local-digest"})),
            "local-digest",
        ),
    ] {
        app.router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .unwrap()
            .study
            .scope_draft
            .as_mut()
            .unwrap()
            .cases[0]
            .threat_model_ref = binding;
        assert!(details(&app).contains(expected));
        assert!(!details(&app).contains("common-digest"));
    }
    app.router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .study
        .scope_draft
        .as_mut()
        .unwrap()
        .proposal_ref
        .revision += 1;
    assert!(details(&app).contains("Scan context: no matching study."));
    assert!(!details(&app).contains("local-digest"));
}

#[test]
fn expanded_tree_keeps_file_identity_and_controls_reachable_at_every_size() {
    let (_root, mut app) = fixture();
    app.set_input("retained command");
    app.set_cursor(4);
    press(&mut app, KeyCode::Right);
    press(&mut app, KeyCode::Down);
    let selected = app.scope_review().unwrap().selected_row();
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.reduce_resize(width, height);
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::render_app(frame, &app))
            .unwrap();
        let buffer = terminal.backend().buffer();
        let text = buffer
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(text.contains("README.md"), "{width}x{height}: {text}");
        assert!(
            text.contains("Enter menu · Esc")
                && text.contains("p plan")
                && text.contains("Tab read")
                && text.contains("f files"),
            "{text}"
        );
        assert_eq!(app.scope_review().unwrap().selected_row(), selected);
    }
    assert_eq!((app.input(), app.cursor()), ("retained command", 4));
}

#[test]
fn file_actions_keep_canonical_identity_and_hide_boundary_only_edits() {
    let (_root, mut app) = fixture();
    press(&mut app, KeyCode::Right);
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.scope_review().unwrap().matching_actions(), [4, 15, 17]);
    assert_eq!(app.scope_review().unwrap().menu, Some(4));
    press(&mut app, KeyCode::Down);
    assert_eq!(app.scope_review().unwrap().menu, Some(15));
    press(&mut app, KeyCode::Enter);
    let form = app.scope_review().unwrap().form.as_ref().unwrap();
    assert_eq!(form.kind, ScopeEditKind::Add);
    assert_eq!(form.fields[1].1.text(), "README.md");
    press(&mut app, KeyCode::Esc);
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Char('/'));
    app.capture_scope_review_paste("Rename scope");
    assert!(app.scope_review().unwrap().matching_actions().is_empty());
    assert!(press(&mut app, KeyCode::Enter).effects.is_empty());
    assert!(app.scope_review().unwrap().form.is_none());
    press(&mut app, KeyCode::Esc);
    assert_eq!(app.scope_review().unwrap().menu, Some(4));
    press(&mut app, KeyCode::Enter);
    assert_eq!(
        app.scope_review().unwrap().form.as_ref().unwrap().kind,
        ScopeEditKind::ExcludePath
    );
}

fn select_branch(app: &mut ShellApp, branch: ScopeBranch) {
    select_row(app, |row| row == &ScopeTreeRow::Branch(branch.clone()));
}
fn select_row(app: &mut ShellApp, predicate: impl Fn(&ScopeTreeRow) -> bool) {
    let cursor = app
        .scope_review()
        .unwrap()
        .tree_rows()
        .iter()
        .position(predicate)
        .unwrap();
    app.router.scope_review_mut().as_mut().unwrap().cursor = cursor;
}
fn details(app: &ShellApp) -> String {
    let state = app.scope_review().unwrap();
    crate::ui_view_models::scope_review::scope_detail_lines(
        app,
        state,
        &crate::ui_view_models::scope_review::scope_source_view(app, state),
        120,
    )
    .join("\n")
}
