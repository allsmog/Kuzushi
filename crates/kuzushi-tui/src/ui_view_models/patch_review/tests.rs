use super::*;

#[test]
fn patch_review_model_copies_pending_patch_for_matching_alias() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.pending_patch = Some(PendingPatch {
        alias: "F-0001".to_string(),
        rationale: "replace string-built SQL".to_string(),
        side_effect: Some("closes finding".to_string()),
        diff: "+query!".to_string(),
        tests: vec![("orders::sqli".to_string(), "reject payload".to_string())],
        guardrail: Some("human-required".to_string()),
        staged_at: Some(".kuzushi/runs/r-1/patch.diff".to_string()),
    });

    let model = patch_review_model(&app, "F-0001").expect("matching patch");

    assert_eq!(model.alias, "F-0001");
    assert_eq!(model.rationale, "replace string-built SQL");
    assert_eq!(model.side_effect.as_deref(), Some("closes finding"));
    assert_eq!(model.diff, "+query!");
    assert_eq!(model.tests[0].name, "orders::sqli");
    assert_eq!(model.tests[0].blurb, "reject payload");
    assert_eq!(model.guardrail.as_deref(), Some("human-required"));
    assert_eq!(
        model.staged_at.as_deref(),
        Some(".kuzushi/runs/r-1/patch.diff")
    );
}

#[test]
fn patch_review_model_ignores_other_aliases() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.pending_patch = Some(PendingPatch {
        alias: "F-0001".to_string(),
        rationale: "rationale".to_string(),
        side_effect: None,
        diff: "+change".to_string(),
        tests: Vec::new(),
        guardrail: None,
        staged_at: None,
    });

    assert!(patch_review_model(&app, "F-9999").is_none());
}
