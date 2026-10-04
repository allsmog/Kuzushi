use super::*;
use kuzushi_core::capabilities::threat_model::{
    commit_threat_model_revision, load_active_threat_model, ScopeRef, ThreatModelCommit,
    ThreatModelRevisionSource,
};
use std::path::Path;

fn setup_fixture() -> (tempfile::TempDir, ShellApp, ContextStudyReceipt) {
    let (root, mut app) = fixture();
    app.router.campaign_mut().batch_scan_config = None;
    app.open_setup();
    app.set_input("unfinished\noperator note");
    app.set_cursor(4);
    app.review_model_backed_map(&[crate::app::PlanningTaskId::BuildThreatModel]);
    let result = prepare(&mut app, root.path());
    app.cache_tool_snapshot("campaign:context-study", &result);
    let config = app.router.campaign_mut().batch_scan_config.as_mut().unwrap();
    config.study.max_provider_calls = Some(5);
    config.study.protected_review_calls = Some(2);
    let (tool, input) = context_action_input(config).unwrap();
    let approved = dispatch(&app, root.path(), tool, input, true);
    app.cache_tool_snapshot(tool, &approved);
    let receipt = app.context_generation().unwrap().receipt.clone().unwrap();
    (root, app, receipt)
}

fn commit(root: &Path, label: &str, run: Option<&str>, activate: bool) -> ThreatModelRef {
    let document = json!({"version":"1","title":label,"dfd":{"nodes":[
        {"id":"app","type":"process","name":label,"trustZone":"internal"}],
        "flows":[],"trustBoundaries":[]},"summary":{},"threats":[]});
    commit_threat_model_revision(root, &document, ThreatModelCommit {
        model_id: None, new_model: true, label: label.into(),
        scope: ScopeRef::legacy_root(root, &format!("sha256:{}", "1".repeat(64))),
        methodology: "stride".into(), source: ThreatModelRevisionSource::Import,
        source_revision_id: None, run_id: run.map(str::to_owned), activate: Some(activate), actor: "test".into(),
    }).unwrap().model_ref
}

fn completed(root: &Path, receipt: &ContextStudyReceipt, run: &str) {
    let path = root.join(".kuzushi/v3/campaigns").join(&receipt.campaign_id).join("queue.json");
    std::fs::write(path, json!({"jobs":{"context-001":{"state":"completed","runId":run,"attempts":1}}}).to_string()).unwrap();
}

fn reopen_setup(app: &mut ShellApp) {
    app.reduce_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert_eq!(app.shell_view(), ShellView::Setup);
    assert_eq!(app.input(), "unfinished\noperator note");
    assert_eq!(app.cursor(), 4);
    app.review_model_backed_map(&[crate::app::PlanningTaskId::BuildThreatModel]);
}

#[test]
fn setup_recovery_inspects_exact_generated_revision_and_preserves_allowance_and_origin() {
    let (root, mut app, receipt) = setup_fixture();
    let active = commit(root.path(), "Other active context", None, true);
    let generated = commit(root.path(), "Generated recovery fixture", Some("context-run"), false);
    completed(root.path(), &receipt, "context-run");
    reopen_setup(&mut app);
    assert_eq!(app.context_generation().unwrap().generated.as_ref(), Some(&generated));
    assert!(app.study_context_picker().is_none());
    let update = app.reduce_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    let [ShellEffect::PrepareRunTool(request)] = update.effects.as_slice() else {
        panic!("exact read must use prepared dispatch")
    };
    assert_eq!(request.tool_name, "threat-model:read");
    let input: Value = serde_json::from_str(request.input.as_ref().unwrap()).unwrap();
    assert_eq!(input["threatModelRef"], json!(generated));
    let result = dispatch(&app, root.path(), &request.tool_name, input, false);
    app.cache_tool_snapshot("threat-model:read", &result);
    assert!(app.context_generation().is_none());
    assert_eq!(app.study_context_picker().unwrap().preview.as_ref().unwrap().document["title"], "Generated recovery fixture");
    app.reduce_key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE));
    assert_same_study(&app, &receipt, &generated);
    assert_eq!(load_active_threat_model(root.path()).unwrap().unwrap().model_ref, active);
    reopen_setup(&mut app);
    assert_eq!(app.context_generation().unwrap().generated.as_ref(), Some(&generated));
}

fn assert_same_study(app: &ShellApp, receipt: &ContextStudyReceipt, generated: &ThreatModelRef) {
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert_eq!(config.study.investigation_id, receipt.investigation_id);
    assert_eq!(config.study.max_provider_calls, Some(5));
    assert_eq!(config.study.protected_review_calls, Some(2));
    assert_eq!(config.study.allowance.as_ref().unwrap().committed_calls, 0);
    assert_eq!(config.study.scan_input.as_ref().unwrap()["threatModelRef"], json!(generated));
    assert_eq!(config.origin.as_ref().unwrap().view, ShellView::Setup);
}

#[test]
fn completed_missing_output_recovers_an_honest_form_and_never_offers_generation_as_pending() {
    let (root, mut app, receipt) = setup_fixture();
    completed(root.path(), &receipt, "missing-output");
    reopen_setup(&mut app);
    assert_missing_output(&app);
    let update = app.reduce_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(update.effects.is_empty());
    assert!(app.router.campaign().batch_scan_config.is_none());
    assert_eq!(app.router.campaign().selected_campaign().unwrap().jobs[0].state, "completed");
    assert!(app.router.campaign().dispatcher_pid.is_none());
    app.restore_context_generation(root.path(), &receipt.campaign_id);
    assert_missing_output(&app);
    app.handle_context_generation_key(KeyCode::Char('n'));
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert_eq!(config.study.investigation_id, receipt.investigation_id);
    assert!(config.context_generation.as_ref().unwrap().receipt.is_none());
    assert_eq!(config.study.allowance.as_ref().unwrap().committed_calls, 0);
}

fn assert_missing_output(app: &ShellApp) {
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    let generation = config.context_generation.as_ref().unwrap();
    assert_eq!(generation.action(config), "Inspect context job outcome");
    assert!(generation.generated.is_none());
    assert!(generation.result_error.as_ref().unwrap().contains("no immutable context manifest"));
    for (width, height) in [(120, 36), (80, 24), (60, 20), (40, 12), (96, 89), (160, 48)] {
        let body = crate::ui_view_models::context_generation::generation_body(width, height);
        let text = crate::ui_view_models::context_generation::generation_lines(app, body.width as usize).join(" ");
        assert!(text.contains("Context result unavailable"));
        assert!(text.contains("replacement draft needs separate approval"));
        assert!(!text.contains("Open approved context job"));
    }
}

#[test]
fn saved_generated_reference_is_invalidated_when_its_output_disappears() {
    let (root, mut app, receipt) = setup_fixture();
    commit(root.path(), "Recovery fixture", Some("context-run"), false);
    completed(root.path(), &receipt, "context-run");
    reopen_setup(&mut app);
    assert!(app.context_generation().unwrap().generated.is_some());
    std::fs::remove_file(root.path().join(".kuzushi/threat-models/manifest.json")).unwrap();
    reopen_setup(&mut app);
    assert_missing_output(&app);
}
