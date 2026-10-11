use super::*;
use kuzushi_core::findings::{Finding, FindingRelationshipKind, FindingStore, Severity};

mod fixture;

#[test]
fn recorded_endpoint_open_and_return_preserve_the_reviewed_pair_side_and_scroll() {
    let (_root, mut app, _store) = fixture::app();
    app.editor_mut().set_input("Retained source-reading draft");
    key(&mut app, KeyCode::Char('*'));
    key(&mut app, KeyCode::Char('A'));
    key(&mut app, KeyCode::Char('j'));
    key(&mut app, KeyCode::Char(']'));
    app.router.default_scroll_mut().set(3);
    let id = app.router.relationships.bulk.as_ref().unwrap().records[1]
        .to
        .finding_id;
    key(&mut app, KeyCode::Enter);
    assert_eq!(app.selected_finding().as_ref().unwrap().id, Some(id));
    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(app.input_mode(), InputMode::Navigate);
    key(&mut app, KeyCode::Char('G'));
    assert_eq!(app.shell_view(), ShellView::Relationships);
    let review = app.router.relationships.bulk.as_ref().unwrap();
    assert_eq!(review.cursor, 1);
    assert!(review.inspecting_destination);
    assert_eq!(app.router.default_scroll().offset(), 3);
    assert_eq!(app.input(), "Retained source-reading draft");
    assert!(!app
        .advisory()
        .notice
        .as_ref()
        .is_some_and(|notice| notice.message == "G returns to the reviewed selection."));
}

fn key(app: &mut ShellApp, code: KeyCode) {
    let update = app.reduce_key(KeyEvent::new(code, KeyModifiers::NONE));
    EffectRuntime::execute(app, update.effects);
}

#[test]
fn review_reason_confirmation_and_cancel_preserve_the_composer_and_origin() {
    let (_root, mut app, store) = fixture::app();
    app.editor_mut().set_input("Retained operator draft");
    app.router.default_scroll_mut().set(2);
    let update = app.reduce_key(KeyEvent::new(KeyCode::Char('*'), KeyModifiers::SHIFT));
    EffectRuntime::execute(&mut app, update.effects);
    key(&mut app, KeyCode::Char('A'));
    key(&mut app, KeyCode::Char('j'));
    assert_eq!(app.router.relationships.bulk.as_ref().unwrap().cursor, 1);
    key(&mut app, KeyCode::Char('a'));
    key(&mut app, KeyCode::Enter);
    assert_eq!(
        app.router.relationships.bulk.as_ref().unwrap().stage,
        RelationshipBulkStage::Reason
    );
    app.paste_relationship_note("Reviewed first line\nReviewed second line");
    key(&mut app, KeyCode::Enter);
    assert_eq!(
        app.router.relationships.bulk.as_ref().unwrap().stage,
        RelationshipBulkStage::Confirm
    );
    assert!(app.runtime_state.relationship_write.is_none());
    assert!(store
        .finding_relationships(None, 50, 0)
        .unwrap()
        .rows
        .iter()
        .all(|row| row.state == FindingRelationshipState::Proposed));
    key(&mut app, KeyCode::Esc);
    key(&mut app, KeyCode::Esc);
    key(&mut app, KeyCode::Esc);
    assert!(app.router.relationships.bulk.is_none());
    assert_eq!(app.router.default_scroll().offset(), 2);
    assert_eq!(app.input(), "Retained operator draft");
    assert_eq!(app.router.relationships.selection.len(), 3);
}

#[test]
fn confirmed_selection_settles_atomically_without_stealing_focus_or_changing_verdicts() {
    let (_root, mut app, store) = fixture::app();
    let before = store.list_all_findings().unwrap();
    key(&mut app, KeyCode::Char('*'));
    key(&mut app, KeyCode::Char('A'));
    key(&mut app, KeyCode::Char('a'));
    app.paste_relationship_note("Reviewed exact owned pairs");
    key(&mut app, KeyCode::Enter);
    key(&mut app, KeyCode::Enter);
    assert!(app.runtime_state.relationship_write.is_some());
    app.toggle_relationship_selection();
    assert_eq!(app.router.relationships.selection.len(), 3);
    app.set_shell_view(ShellView::Activity);
    let started = std::time::Instant::now();
    while !app.poll_relationship_write() {
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert_eq!(app.shell_view(), ShellView::Activity);
    assert!(app.router.relationships.selection.is_empty());
    assert!(store
        .finding_relationships(None, 50, 0)
        .unwrap()
        .rows
        .iter()
        .all(|row| row.state == FindingRelationshipState::Accepted));
    assert_eq!(store.list_all_findings().unwrap(), before);
    assert!(store.list_all_review_decisions().unwrap().is_empty());
}

#[test]
fn failed_batch_preserves_the_note_and_captured_versions_for_an_honest_refresh() {
    let (_root, mut app, store) = fixture::app();
    key(&mut app, KeyCode::Char('*'));
    key(&mut app, KeyCode::Char('A'));
    key(&mut app, KeyCode::Char('a'));
    app.paste_relationship_note("Retained batch reason");
    key(&mut app, KeyCode::Enter);
    let draft = app.router.relationships.bulk.take().unwrap();
    store
        .review_finding_relationship(
            &draft.records[2].id,
            FindingRelationshipState::Rejected,
            "Separate concurrent review",
            1,
        )
        .unwrap();
    let result = kuzushi_core::workspace::record_finding_relationship_batch_review(
        &kuzushi_core::WorkspaceTarget::new(app.target_owned().unwrap()).unwrap(),
        &app.config().clone(),
        &kuzushi_core::workspace::FindingRelationshipBatchReviewRequest {
            relationships: draft.records.clone(),
            state: draft.state,
            note: draft.field.text().into(),
        },
    )
    .map(|_| ())
    .map_err(|error| format!("{error:#}"));
    assert!(result.is_err());
    app.finish_relationship_write(
        app.target_owned().unwrap(),
        RelationshipWriteDraft::Batch(draft),
        result,
    );
    let restored = app.router.relationships.bulk.as_ref().unwrap();
    assert_eq!(restored.field.text(), "Retained batch reason");
    assert!(restored.records.iter().all(|row| row.revision == 1));
    assert_eq!(
        store
            .finding_relationships(None, 50, 0)
            .unwrap()
            .rows
            .iter()
            .filter(|row| row.state == FindingRelationshipState::Proposed)
            .count(),
        2
    );
    assert!(app
        .router
        .relationships
        .notice
        .as_ref()
        .unwrap()
        .contains("not confirmed"));
}

#[test]
fn confirmation_refuses_target_switch_and_all_viewports_keep_the_action_owner_clear() {
    let (_root, mut app, _store) = fixture::app();
    key(&mut app, KeyCode::Char('*'));
    key(&mut app, KeyCode::Char('A'));
    key(&mut app, KeyCode::Char('a'));
    app.paste_relationship_note("Reviewed target binding");
    key(&mut app, KeyCode::Enter);
    for (width, height) in [(160, 48), (120, 36), (96, 89), (80, 24), (60, 20), (40, 12)] {
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let text = format!("{:?}", terminal.backend().buffer());
        assert!(text.contains("CONFIRM Accept 3"), "{width}: {text}");
        assert!(text.contains("record all"), "{width}: {text}");
        assert!(!text.contains("Esc prompt"), "{width}: {text}");
    }
    let other = tempfile::tempdir().unwrap();
    app.set_target(Some(other.path().into()));
    key(&mut app, KeyCode::Enter);
    assert!(app.runtime_state.relationship_write.is_none());
    assert!(app
        .router
        .relationships
        .notice
        .as_ref()
        .unwrap()
        .contains("Target changed"));
}
