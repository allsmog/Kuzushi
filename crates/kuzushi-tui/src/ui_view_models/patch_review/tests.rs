use super::*;
use crate::ui_view_models::ui_run_artifact_relative_path;

#[test]
fn patch_review_model_copies_pending_patch_for_matching_alias() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.engagement.set_pending_patch(PendingPatch {
        alias: "F-0001".to_string(),
        patch_run_id: "patch-fixture".to_string(),
        status: kuzushi_core::PatchStatus::Sound,
        rationale: "replace string-built SQL".to_string(),
        side_effect: Some("closes finding".to_string()),
        diff: "+query!".to_string(),
        tests: vec![("orders::sqli".to_string(), "reject payload".to_string())],
        guardrail: Some("human-required".to_string()),
        staged_at: Some(ui_run_artifact_relative_path("r-1", "patch.diff")),
    });

    let model = patch_review_model(&app, "F-0001").expect("matching patch");

    assert_eq!(model.alias, "F-0001");
    assert_eq!(model.patch_run_id, "patch-fixture");
    assert_eq!(model.status, "SOUND");
    assert_eq!(model.rationale, "replace string-built SQL");
    assert_eq!(model.side_effect.as_deref(), Some("closes finding"));
    assert_eq!(model.diff, "+query!");
    assert_eq!(model.tests[0].name, "orders::sqli");
    assert_eq!(model.tests[0].blurb, "reject payload");
    assert_eq!(model.guardrail.as_deref(), Some("human-required"));
    assert_eq!(
        model.staged_at.as_deref(),
        Some(ui_run_artifact_relative_path("r-1", "patch.diff").as_str())
    );
}

#[test]
fn patch_review_model_ignores_other_aliases() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.engagement.set_pending_patch(PendingPatch {
        alias: "F-0001".to_string(),
        patch_run_id: "patch-fixture".to_string(),
        status: kuzushi_core::PatchStatus::Sound,
        rationale: "rationale".to_string(),
        side_effect: None,
        diff: "+change".to_string(),
        tests: Vec::new(),
        guardrail: None,
        staged_at: None,
    });

    assert!(patch_review_model(&app, "F-9999").is_none());
}
