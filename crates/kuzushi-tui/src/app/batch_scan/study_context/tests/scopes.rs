use super::*;
use kuzushi_core::capabilities::campaign::{ScopeStudyCaseInput, ScopeStudyDraft};
use kuzushi_core::workspace::ScanScopeProposalRef;

#[test]
fn exact_scope_override_requires_inspection_and_never_activates_or_changes_siblings() {
    let (root, mut app, first, second) = fixture();
    let config = app
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap();
    config.context_picker = None;
    config.study.scan_input = Some(json!({"threatModelRef":second}));
    config.study.scope_draft = Some(ScopeStudyDraft {
        proposal_ref: ScanScopeProposalRef {
            proposal_id: "owned-fixture".into(),
            revision: 1,
            record_hash: "a".repeat(64),
        },
        cases: ["app", "other"]
            .into_iter()
            .map(|id| ScopeStudyCaseInput {
                scope_id: id.into(),
                passes: 3,
                threat_model_ref: None,
            })
            .collect(),
    });
    app.open_study_context_surface();
    app.handle_scope_context_key(KeyCode::Down);
    app.handle_scope_context_key(KeyCode::Enter);
    app.handle_study_context_key(KeyCode::Up);
    app.handle_study_context_key(KeyCode::Char('a'));
    assert!(app.study_context_picker().is_some());
    assert!(app
        .scope_context_config()
        .unwrap()
        .study
        .scope_draft
        .as_ref()
        .unwrap()
        .cases[0]
        .threat_model_ref
        .is_none());
    let result = inspect(&app, root.path(), &first);
    app.cache_tool_snapshot("threat-model:read", &result);
    app.handle_study_context_key(KeyCode::Char('a'));
    let config = app.scope_context_config().unwrap();
    assert!(config.context_picker.is_none());
    assert_eq!(config.scope_context.cursor, 1);
    let cases = &config.study.scope_draft.as_ref().unwrap().cases;
    assert_eq!(cases[0].threat_model_ref, Some(json!(first)));
    assert_eq!(cases[1].threat_model_ref, None);
    assert_eq!(
        config.study.scan_input.as_ref().unwrap()["threatModelRef"],
        json!(second)
    );
    assert_eq!(
        load_active_threat_model(root.path())
            .unwrap()
            .unwrap()
            .model_ref,
        second
    );
}
