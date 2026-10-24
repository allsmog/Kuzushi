use super::*;
use kuzushi_core::capabilities::campaign::{ScopeStudyCaseInput, ScopeStudyDraft};
use kuzushi_core::{workspace::ScanScopeProposalRef, V2Config};
use serde_json::json;

fn app() -> ShellApp {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(std::env::temp_dir()));
    app.open_batch_scan_config(None);
    let config = app
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap();
    config.study.scan_input = Some(json!({"threatModelRef":null}));
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
    app
}

#[test]
fn scope_context_names_precede_identity_and_do_not_change_associations() {
    let mut app = app();
    let config = app
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap();
    config.scope_context.labels = [
        ("app".into(), "Service".into()),
        ("other".into(), "Root files".into()),
    ]
    .into();
    assert_eq!(
        scope_context::rows(config),
        vec![
            "Common context",
            "Service · inherits common",
            "Root files · inherits common"
        ]
    );
    app.handle_scope_context_key(KeyCode::Down);
    app.handle_scope_context_key(KeyCode::Char('o'));
    let config = app.scope_context_config().unwrap();
    assert!(config
        .notice
        .as_deref()
        .unwrap()
        .contains("Context selected for Service"));
    let detail = scope_context::detail(config, 120).join("\n");
    assert!(detail.contains("Boundary: Service") && detail.contains("Boundary id: app"));
    assert_eq!(
        config.study.scope_draft.as_ref().unwrap().cases[1].threat_model_ref,
        None
    );
}

#[test]
fn omission_and_inheritance_preserve_common_sibling_and_allowance() {
    let mut app = app();
    let before = app.scope_context_config().unwrap().study.clone();
    app.handle_scope_context_key(KeyCode::Down);
    app.handle_scope_context_key(KeyCode::Char('o'));
    let config = app.scope_context_config().unwrap();
    let draft = config.study.scope_draft.as_ref().unwrap();
    assert_eq!(draft.cases[0].threat_model_ref, Some(Value::Null));
    assert_eq!(draft.cases[1].threat_model_ref, None);
    assert_eq!(config.study.scan_input, before.scan_input);
    assert_eq!(config.study.investigation_id, before.investigation_id);
    assert_eq!(config.study.allowance, before.allowance);
    app.handle_scope_context_key(KeyCode::Char('i'));
    assert_eq!(
        app.scope_context_config()
            .unwrap()
            .study
            .scope_draft
            .as_ref()
            .unwrap()
            .cases[0]
            .threat_model_ref,
        None
    );
}

#[test]
fn picker_cancel_restores_boundary_origin_and_scroll() {
    let mut app = app();
    app.handle_scope_context_key(KeyCode::Down);
    app.router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .scope_context
        .scroll = 5;
    app.handle_scope_context_key(KeyCode::Enter);
    assert_eq!(
        app.study_context_picker().unwrap().scope_id.as_deref(),
        Some("app")
    );
    app.handle_study_context_key(KeyCode::Esc);
    assert!(app.study_context_picker().is_none());
    assert_eq!(app.scope_context_config().unwrap().scope_context.cursor, 1);
    assert_eq!(app.scope_context_config().unwrap().scope_context.scroll, 5);
    assert_eq!(
        app.scope_context_config()
            .unwrap()
            .study
            .scope_draft
            .as_ref()
            .unwrap()
            .cases[0]
            .threat_model_ref,
        None
    );
}

#[test]
fn common_omission_requires_common_picker_and_scoped_generation_is_draft_only() {
    let mut app = app();
    app.handle_scope_context_key(KeyCode::Char('o'));
    assert!(app
        .scope_context_config()
        .unwrap()
        .notice
        .as_ref()
        .unwrap()
        .contains("Choose a boundary"));
    app.handle_scope_context_key(KeyCode::Down);
    app.handle_scope_context_key(KeyCode::Enter);
    app.handle_study_context_key(KeyCode::Char('g'));
    let generation = app.context_generation().unwrap();
    assert!(generation.is_scope_context());
    assert_eq!(generation.context_input["scanScopeRef"]["scopeId"], "app");
    assert!(generation.receipt.is_none());
    assert!(app.open_context_matrix().effects.is_empty());
    assert!(!app.scope_context_config().unwrap().study.matrix.open);
    assert!(app.toggle_context_experiment().effects.is_empty());
}

#[test]
fn disappeared_boundary_is_an_error_without_common_mutation() {
    let mut app = app();
    let before = app.scope_context_config().unwrap().study.clone();
    app.apply_scope_context("gone", Some(Value::Null));
    assert_eq!(app.scope_context_config().unwrap().study, before);
    assert!(app
        .scope_context_config()
        .unwrap()
        .notice
        .as_ref()
        .unwrap()
        .contains("no longer"));
}

#[test]
fn changed_binding_retires_plan_identity_but_preserves_limits() {
    let mut app = app();
    let config = app
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap();
    config.study.campaign_id = Some("approved-draft".into());
    config.study.max_provider_calls = Some(8);
    config.study.protected_review_calls = Some(2);
    let investigation = config.study.investigation_id.clone();
    app.apply_scope_context("app", Some(Value::Null));
    let config = app.scope_context_config().unwrap();
    assert!(config.study.campaign_id.is_none());
    assert_eq!(config.study.investigation_id, investigation);
    assert_eq!(config.study.max_provider_calls, Some(8));
    assert_eq!(config.study.protected_review_calls, Some(2));
}

#[test]
fn plain_projection_discloses_selection_and_paging_keeps_controls() {
    let mut app = app();
    app.handle_scope_context_key(KeyCode::Down);
    app.handle_scope_context_key(KeyCode::Char('o'));
    let config = app.scope_context_config().unwrap();
    let detail = scope_context::detail(config, 38).join(" ");
    let detail = detail.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(detail.contains("Boundary: app"));
    assert!(detail.contains("explicitly omitted"));
    for width in [38, 58, 78, 118, 158] {
        assert!(scope_context::controls(width)[1].contains("Esc back"));
    }
}
