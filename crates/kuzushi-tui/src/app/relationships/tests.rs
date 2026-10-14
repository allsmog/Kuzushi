use super::*;
use kuzushi_core::findings::{Finding, FindingRelationshipKind, FindingStore, Severity};

fn fixture() -> (tempfile::TempDir, ShellApp, FindingRelationship) {
    let root = tempfile::tempdir().unwrap();
    let workspace = kuzushi_core::WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    for (run, rule) in [("owned-a", "a"), ("owned-b", "b")] {
        store
            .record_run_started(run, root.path(), "completed")
            .unwrap();
        store
            .insert_finding(
                run,
                &Finding::new_tool(
                    "owned-fixture",
                    rule,
                    "hello.txt",
                    1,
                    None,
                    Severity::Info,
                    "Labeled relationship fixture",
                ),
            )
            .unwrap();
    }
    let findings = store.list_all_findings().unwrap();
    let relation = store
        .propose_finding_relationship(
            findings[0].id.unwrap(),
            findings[1].id.unwrap(),
            FindingRelationshipKind::Duplicate,
            "Labeled same observation",
            Some(0.95),
        )
        .unwrap();
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), Some(&workspace));
    app.refresh_findings_effect(FindingsRefresh {
        announce: false,
        filter: None,
    });
    app.set_shell_view(ShellView::Workbench);
    app.editor_mut().set_input("preserve operator draft");
    app.open_relationships();
    app.router.relationships.finding_id = None;
    app.workbench_cache()
        .borrow_mut()
        .apply_view_hydration(ViewHydrationResult {
            target: workspace.root().into(),
            key: ViewHydrationKey::FindingRelationships {
                finding_id: None,
                offset: 0,
            },
            value: ViewHydrationValue::FindingRelationships(Ok(store
                .finding_relationships(None, 50, 0)
                .unwrap())),
        });
    (root, app, relation)
}

#[test]
fn failed_relationship_save_restores_the_note_and_its_error_with_a_nonempty_draft() {
    let (root, mut app, _) = fixture();
    app.begin_relationship_note(FindingRelationshipState::Accepted);
    app.paste_relationship_note("Retained reason");
    let draft = app.router.relationships.note.take().unwrap();
    app.finish_relationship_write(
        kuzushi_core::WorkspaceTarget::new(root.path())
            .unwrap()
            .root()
            .into(),
        draft,
        Err("relationship changed; refresh before deciding".into()),
    );
    assert_eq!(
        app.router.relationships.note.as_ref().unwrap().field.text(),
        "Retained reason"
    );
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(40, 12)).unwrap();
    terminal
        .draw(|frame| crate::renderer::render_app(frame, &app))
        .unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());
    assert!(
        rendered.contains("Relationship decision not confirmed"),
        "{rendered}"
    );
    assert!(rendered.contains("relationship changed"), "{rendered}");
    assert!(rendered.contains("Esc cancel"), "{rendered}");
    assert_eq!(app.input(), "preserve operator draft");
}

#[test]
fn note_editor_owns_paste_and_cancellation_preserves_the_original_composer() {
    let (_root, mut app, _) = fixture();
    app.begin_relationship_note(FindingRelationshipState::Accepted);
    assert!(app.paste_relationship_note("A multiline\nUnicode reason: café"));
    assert_eq!(
        app.router.relationships.note.as_ref().unwrap().field.text(),
        "A multiline\nUnicode reason: café"
    );
    app.handle_relationship_note_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(app.router.relationships.note.is_none());
    assert_eq!(app.input(), "preserve operator draft");
    assert_eq!(app.router.overlay_origin(), Some(ShellView::Workbench));
}

#[test]
fn empty_reason_and_target_switch_refuse_a_write_without_losing_the_note() {
    let (_root, mut app, _) = fixture();
    app.begin_relationship_note(FindingRelationshipState::Accepted);
    app.submit_relationship_note();
    assert!(app.runtime_state.relationship_write.is_none());
    assert!(app
        .router
        .relationships
        .notice
        .as_deref()
        .unwrap()
        .contains("reason"));
    app.paste_relationship_note("Reviewed source pairs");
    let other = tempfile::tempdir().unwrap();
    app.set_target(Some(other.path().into()));
    app.submit_relationship_note();
    assert!(app.runtime_state.relationship_write.is_none());
    assert!(app.router.relationships.note.is_some());
    assert_eq!(app.input(), "preserve operator draft");
}

#[test]
fn relationship_notes_show_their_actual_controls_in_every_viewport() {
    let (_root, mut app, _) = fixture();
    app.set_input_mode(InputMode::Navigate);
    app.begin_relationship_note(FindingRelationshipState::Accepted);
    app.paste_relationship_note(
        "Reviewed the two observations.\nGrouping is separate from verdicts.",
    );
    for (width, height) in [(160, 48), (120, 36), (96, 89), (80, 24), (60, 20), (40, 12)] {
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());
        assert!(rendered.contains("Enter record"), "{width}: {rendered}");
        assert!(rendered.contains("Accept: F-"), "{width}: {rendered}");
        assert!(rendered.contains("Esc cancel"), "{width}: {rendered}");
        assert!(!rendered.contains("Esc prompt"), "{width}: {rendered}");
        assert!(!rendered.contains("a accept"), "{width}: {rendered}");
    }
}

#[test]
fn narrow_relationship_browser_keeps_primary_actions_and_complete_aliases_visible() {
    let (_root, mut app, _) = fixture();
    app.set_input_mode(InputMode::Navigate);
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(40, 12)).unwrap();
    terminal
        .draw(|frame| crate::renderer::render_app(frame, &app))
        .unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());
    assert!(rendered.contains("a accept"), "{rendered}");
    assert!(rendered.contains("u unlink"), "{rendered}");
    assert!(rendered.contains("F-0001"), "{rendered}");
    assert!(rendered.contains("F-0002"), "{rendered}");
}

#[test]
fn accepted_relationship_settles_in_background_without_changing_view_or_finding_verdicts() {
    let (root, mut app, relation) = fixture();
    app.begin_relationship_note(FindingRelationshipState::Accepted);
    app.paste_relationship_note("Reviewed both recorded observations");
    app.submit_relationship_note();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !app.poll_relationship_write() {
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert_eq!(app.shell_view(), ShellView::Relationships);
    assert_eq!(app.input(), "preserve operator draft");
    let workspace = kuzushi_core::WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open_read_only(workspace.findings_db_path()).unwrap();
    assert_eq!(
        store
            .finding_relationship(&relation.id)
            .unwrap()
            .unwrap()
            .state,
        FindingRelationshipState::Accepted
    );
    let findings = store.list_all_findings().unwrap();
    assert_eq!(findings.len(), 2);
    assert!(store.list_all_review_decisions().unwrap().is_empty());
}
