use super::*;
use serde_json::json;

#[cfg(unix)]
#[test]
fn approved_scan_persists_one_observation_and_settles_one_offline_request() {
    let _env_lock = env_test_lock();
    let _api_key = EnvVarGuard::set("OPENAI_API_KEY", "test-key");
    let target = tempfile::tempdir().unwrap();
    let adapter = tempfile::tempdir().unwrap();
    let source = "Owned inert documentation for admission and persistence testing.\n";
    fs::write(target.path().join("example.txt"), source).unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    let bridge = prepared_dispatch::admitted_fixture_bridge(
        adapter.path(),
        "owned-observation",
        json!({"ok":true,"structured":{"findings":[{
            "ruleId":"owned/synthetic-observation", "filePath":"example.txt",
            "startLine":1, "severity":"INFO", "confidence":"LOW",
            "message":"Synthetic owned observation", "evidence":"Fixture data, not a detected vulnerability"
        }]}}),
    );
    let mut config = V2Config::default();
    config.model = Some("openai:gpt-4.1".into());
    config.runtime.kind = RuntimeKind::LangGraph;
    config.runtime.api_key_env = "OPENAI_API_KEY".into();
    config.runtime.langgraph_bridge_command = Some(vec![bridge.display().to_string()]);
    prepared_dispatch::build_fixture_context(&config, &workspace);
    let allowance = prepared_dispatch::approve_model_work(&config, &workspace);
    let mut app = ShellApp::new(config, Some(&workspace));
    run_command(&mut app, ShellCommand::Use("agentic-sast".into()));
    run_command(
        &mut app,
        ShellCommand::RunTool {
            tool: None,
            input: Some(json!({"maxFindings":1,"allowanceRef":allowance}).to_string()),
        },
    );
    drain_chain_with_auto_reuse(&mut app);
    assert_scan_receipt_and_observation(&app, &workspace);
    assert_eq!(
        fs::read_to_string(target.path().join("example.txt")).unwrap(),
        source
    );
    assert_scan_allowance(&workspace);
}

#[cfg(unix)]
fn assert_scan_receipt_and_observation(app: &ShellApp, workspace: &WorkspaceTarget) {
    assert_eq!(app.shell_view(), ShellView::Activity);
    assert!(
        app.log_lines().iter().any(|line| {
            line.prefix == "result" && line.body.contains("agentic-sast: 1 finding")
        }),
        "{:?}",
        app.log_lines()
    );
    let run = &app.activity().unwrap().run_id;
    let projection =
        kuzushi_core::run_lifecycle::load_run_projection(workspace.root(), run).unwrap();
    let summaries = projection.presentation_hydration.verified_summaries();
    assert_eq!(summaries.len(), 1, "{projection:?}");
    assert_eq!(summaries[0].status, "completed");
    let result: serde_json::Value = serde_json::from_slice(
        &fs::read(run_dir(workspace.root(), run).join("result.json")).unwrap(),
    )
    .unwrap();
    let scan = result["data"]["persisted"]["runId"].as_str().unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let findings = store.list_all_findings().unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].tool, "agentic");
    assert_eq!(
        findings[0].message,
        "Synthetic owned observation\n\nEvidence: Fixture data, not a detected vulnerability\nConfidence: LOW"
    );
    assert_eq!(
        store
            .count_finding_observations_for_scan_ids(&[scan])
            .unwrap(),
        1
    );
}

#[cfg(unix)]
fn assert_scan_allowance(workspace: &WorkspaceTarget) {
    let ledger = kuzushi_core::SpendLimiter::open(workspace.findings_db_path()).unwrap();
    let allowance = ledger.allowance_snapshot("dispatch-fixture").unwrap();
    assert_eq!(allowance.committed_calls, 1, "{allowance:?}");
    assert_eq!(allowance.unresolved_calls, 0);
    assert_eq!(allowance.protected_review_remaining(), 2);
}
