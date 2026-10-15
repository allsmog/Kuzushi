use super::*;
use kuzushi_core::modules::{ModuleRegistry, ToolExecutionContext};
use serde_json::{json, Value};

#[cfg(unix)]
pub(super) fn admitted_fixture_bridge(dir: &Path, name: &str, response: Value) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let module = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/langgraph-bridge/provider-admission.mjs");
    let path = dir.join(format!("{name}-bridge.mjs"));
    let script = format!(
        r#"#!/usr/bin/env node
import assert from 'node:assert/strict';
import {{ pathToFileURL }} from 'node:url';
const {{ readBridgeRequest, openProviderAdmission, withProviderAdmission }} =
    await import(pathToFileURL({module}).href);
globalThis.fetch = () => {{ throw new Error('No network in the owned fixture'); }};
const write = text => new Promise(resolve => process.stdout.write(text, resolve));
const request = await readBridgeRequest(process.stdin);
assert.equal(request.providerAdmission, 'stdio-v1');
await openProviderAdmission(request, write);
const result = await withProviderAdmission(request, async () => ({{...{response}, costUsd: 0}}), () => ({{costUsd: 0}}));
await write('\x1e' + JSON.stringify({{type:'result', result}}) + '\n');
process.stdin.destroy();
"#,
        module = serde_json::to_string(&module).unwrap(),
    );
    fs::write(&path, script).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

pub(super) fn approve_model_work(config: &V2Config, workspace: &WorkspaceTarget) -> Value {
    let registry = ModuleRegistry::with_v2_builtins();
    let ctx = ToolExecutionContext {
        config,
        workspace: Some(workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let input = json!({
        "investigationId":"dispatch-fixture", "expectedRevision":0,
        "model":config.model, "maxProviderCalls":4, "protectedReviewCalls":2,
        "reason":"Owned local bridge fixture; no live provider requests"
    });
    let prepared = registry
        .prepare_dispatch_input("campaign:approve-allowance", input, &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap();
    json!({"schemaVersion":1,"investigationId":"dispatch-fixture","revision":1,"workId":"one-tool"})
}

pub(super) fn assert_settled_model_work(workspace: &WorkspaceTarget) {
    let ledger = kuzushi_core::SpendLimiter::open(workspace.findings_db_path()).unwrap();
    let snapshot = ledger.allowance_snapshot("dispatch-fixture").unwrap();
    assert!(snapshot.committed_calls > 0, "{snapshot:?}");
    assert!(snapshot.committed_calls <= 4, "{snapshot:?}");
    assert_eq!(snapshot.unresolved_calls, 0);
}

pub(super) fn build_fixture_context(config: &V2Config, workspace: &WorkspaceTarget) {
    let registry = ModuleRegistry::with_v2_builtins();
    let ctx = ToolExecutionContext {
        config,
        workspace: Some(workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let prepared = registry
        .prepare_dispatch_input("context:build", json!({"enrichment":false}), &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    let result = registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap();
    assert_eq!(
        kuzushi_core::tool_result_status(&result),
        kuzushi_core::ToolResultStatus::Completed
    );
}

#[test]
fn prepared_model_activity_does_not_claim_a_request_before_admission() {
    for tool in ["threat-model:build", "triage:run", "agentic-sast:scan"] {
        let activity = live_activity_for_prepared_tool(tool, tool_run_status(tool), true);
        assert_eq!(activity.phase, LiveActivityPhase::RunningTool);
        assert_eq!(activity.detail, "preparing model work");
        assert!(!activity.transcript_line().contains("calling model"));
    }
}

#[cfg(unix)]
#[test]
fn unapproved_review_reports_refusal_without_invoking_the_bridge() {
    assert_unapproved_model_work("triage:run");
}

#[cfg(unix)]
#[test]
fn unapproved_scan_reports_refusal_without_invoking_the_bridge() {
    assert_unapproved_model_work("agentic-sast:scan");
}

#[cfg(unix)]
fn assert_unapproved_model_work(tool: &str) {
    use std::os::unix::fs::PermissionsExt;
    let _env_lock = env_test_lock();
    let _api_key = EnvVarGuard::set("OPENAI_API_KEY", "test-key");
    let target = tempfile::tempdir().unwrap();
    let adapter = tempfile::tempdir().unwrap();
    fs::write(
        target.path().join("example.txt"),
        "Owned inert documentation.\n",
    )
    .unwrap();
    let marker = adapter.path().join("unexpected-request");
    let bridge = adapter.path().join("refuse.sh");
    let quoted_marker = marker.to_string_lossy().replace('\'', "'\\''");
    fs::write(
        &bridge,
        format!("#!/bin/sh\nprintf 'called' > '{quoted_marker}'\nexit 99\n"),
    )
    .unwrap();
    fs::set_permissions(&bridge, fs::Permissions::from_mode(0o700)).unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    let mut config = V2Config::default();
    config.model = Some("openai:gpt-4.1".into());
    config.runtime.kind = RuntimeKind::LangGraph;
    config.runtime.api_key_env = "OPENAI_API_KEY".into();
    config.runtime.langgraph_bridge_command = Some(vec![bridge.display().to_string()]);
    build_fixture_context(&config, &workspace);
    let mut app = ShellApp::new(config, Some(&workspace));
    run_command(
        &mut app,
        ShellCommand::RunTool {
            tool: Some(tool.into()),
            input: Some(json!({"strategy":"standard"}).to_string()),
        },
    );
    if app.engagement.has_pending_prereq_prompt() {
        let effects = app.resolve_prereq_plan(PrereqPlanAction::Reuse);
        EffectRuntime::execute(&mut app, effects);
    }
    assert_eq!(app.live_activity().unwrap().detail, "preparing model work");
    drain_tool(&mut app);
    assert!(!marker.exists(), "unapproved work invoked the bridge");
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.body.contains("no model request started")));
    assert!(!app
        .log_lines()
        .iter()
        .any(|line| line.body.contains("calling model")));
    assert_eq!(
        app.live_activity().unwrap().phase,
        LiveActivityPhase::Refused
    );
    let run = app.activity().unwrap().run_id.clone();
    let projection = kuzushi_core::run_lifecycle::load_run_projection(target.path(), &run).unwrap();
    let summaries = projection.presentation_hydration.verified_summaries();
    assert_eq!(summaries.len(), 1, "{projection:?}");
    assert_eq!(summaries[0].status, "blocked");
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    assert!(store.list_all_findings().unwrap().is_empty());
}
