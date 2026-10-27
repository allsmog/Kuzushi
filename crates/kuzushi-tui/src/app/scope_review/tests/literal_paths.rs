use super::*;

pub(super) fn literal_fixture() -> (tempfile::TempDir, ShellApp) {
    let (root, mut app) = fixture();
    std::fs::create_dir(root.path().join(" auth ")).unwrap();
    std::fs::write(
        root.path().join(" auth /owned.rs"),
        "// Owned inert source\n",
    )
    .unwrap();
    let update = press(&mut app, KeyCode::Char('c'));
    finish(&mut app, root.path(), update).unwrap();
    (root, app)
}

#[test]
fn literal_scope_exclusion_never_targets_the_trimmed_directory() {
    let (root, mut app) = literal_fixture();
    app.apply_scope_menu(4);
    fill_form(&mut app, &[" auth ", "Defer the literal spaced directory"]);
    let update = press(&mut app, KeyCode::F(2));
    finish(&mut app, root.path(), update).unwrap();
    let review = app.scope_review().unwrap().review.as_ref().unwrap();
    assert_eq!(review.coverage.excluded_files.files, [" auth /owned.rs"]);
    assert!(review.coverage.discovery_members["repository"]
        .files
        .contains(&"auth/login.rs".into()));
    assert!(review.record.acceptance.is_none());
}

#[test]
fn literal_scope_split_keeps_each_exact_membership_without_overlap() {
    let (root, mut app) = literal_fixture();
    app.apply_scope_menu(1);
    fill_form(
        &mut app,
        &["Spaced auth", " auth ", "Other source", "auth\nREADME.md"],
    );
    let update = press(&mut app, KeyCode::F(2));
    finish(&mut app, root.path(), update).unwrap();
    let review = app.scope_review().unwrap().review.as_ref().unwrap();
    let scope = &review.record.draft.scopes[0];
    assert_eq!(scope.paths, [" auth "]);
    assert_eq!(
        review.coverage.discovery_members[&scope.id].files,
        [" auth /owned.rs"]
    );
    assert_eq!(review.coverage.uncovered_files.total, 0);
    assert_eq!(review.coverage.overlaps.total, 0);
    assert!(review.record.acceptance.is_none());
    assert!(crate::ui_view_models::scope_review::scope_detail(
        app.scope_review().unwrap(),
        Vec::new()
    )
    .iter()
    .any(|line| line == "Boundary: \" auth \""));
}

#[test]
fn literal_scope_file_reading_marks_edge_spaces_at_every_viewport() {
    let (root, mut app) = literal_fixture();
    let update = press(&mut app, KeyCode::Char('f'));
    finish(&mut app, root.path(), update).unwrap();
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.reduce_resize(width, height);
        app.router.scope_review_mut().as_mut().unwrap().scroll = 0;
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        let mut pages = String::new();
        for _ in 0..20 {
            terminal
                .draw(|frame| crate::render_app(frame, &app))
                .unwrap();
            let buffer = terminal.backend().buffer();
            for y in 0..height {
                pages.push_str(
                    &(0..width)
                        .map(|x| buffer[(x, y)].symbol())
                        .collect::<String>(),
                );
                pages.push('\n');
            }
            press(&mut app, KeyCode::PageDown);
        }
        assert!(pages.contains("\" auth /owned.rs\""), "{width}x{height}");
    }
}

#[test]
fn literal_scope_unknown_path_cannot_turn_into_a_whole_repository_exclusion() {
    let (root, mut app) = literal_fixture();
    let original = app.scope_review().unwrap().review.clone();
    app.apply_scope_menu(4);
    fill_form(&mut app, &[" . ", "Must not exclude the repository"]);
    let update = press(&mut app, KeyCode::F(2));
    assert!(finish(&mut app, root.path(), update).is_err());
    assert_eq!(app.scope_review().unwrap().review, original);
    assert!(!root.path().join(".kuzushi/v3/campaigns").exists());
}
