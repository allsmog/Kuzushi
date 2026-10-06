use super::*;
use crate::run_artifacts::*;
use crate::{ModuleRegistry, TraceHandle, V2Config, WorkspaceTarget};

fn fixture() -> (tempfile::TempDir, crate::ThreatModelRef) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("app.py"),
        "from flask import Flask\nweb = Flask(__name__)\n@web.get('/health')\ndef health(): pass\n",
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config::default();
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let ctx = context(&workspace, &config, None);
    for (tool, input) in [
        ("context:build", json!({"enrichment":false})),
        ("entry-points:extract", json!({})),
    ] {
        let prepared = registry
            .prepare_dispatch_input(tool, input, &ctx, None)
            .unwrap();
        registry
            .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
            .unwrap();
    }
    let trace = TraceHandle::jsonl(root.path(), "standalone-context");
    let ctx = context(&workspace, &config, Some(&trace));
    let prepared = registry
        .prepare_dispatch_input(
            "threat-model:build",
            json!({"pipeline":"deterministic", "offline":true,"variantScan":false}),
            &ctx,
            None,
        )
        .unwrap()
        .authorize_explicit_headless();
    let record = ToolRunRecord::new(
        root.path(),
        "standalone-context",
        "tool",
        "threat-model:build",
    );
    try_record_tool_run_started_with_reproducibility(
        record,
        prepared.value(),
        None,
        None,
        Vec::new(),
    )
    .unwrap();
    let observed = registry
        .dispatch_prepared_input_observed_with_runtime(prepared, &ctx, None)
        .unwrap();
    let output = observed.execution.unwrap();
    assert_eq!(output["status"], "partial");
    try_record_tool_run_complete_settled(
        record,
        &output,
        &trace.run_observation().unwrap(),
        observed.completion,
    )
    .unwrap();
    let reference = serde_json::from_value(output["data"]["modelRef"].clone()).unwrap();
    (root, reference)
}

fn context<'a>(
    workspace: &'a WorkspaceTarget,
    config: &'a V2Config,
    trace: Option<&'a TraceHandle>,
) -> ToolExecutionContext<'a> {
    ToolExecutionContext {
        config,
        workspace: Some(workspace),
        findings_store: None,
        trace,
        cancellation: None,
        authorization: Default::default(),
    }
}

fn review(root: &Path, input: Value) -> Result<Value> {
    let workspace = WorkspaceTarget::new(root)?;
    let config = V2Config::default();
    let ctx = context(&workspace, &config, None);
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let prepared = registry
        .prepare_dispatch_input("campaign:context-map", input, &ctx, None)?
        .authorize_explicit_headless();
    registry.dispatch_prepared_input_with_runtime(prepared, &ctx, None)
}

#[test]
fn existing_partial_context_requires_acknowledgement_and_reopens_without_new_work() {
    let (root, reference) = fixture();
    let active = crate::capabilities::threat_model::load_active_threat_model(root.path())
        .unwrap()
        .map(|model| model.model_ref);
    let input = json!({"threatModelRef":reference});
    let first = review(root.path(), input.clone()).unwrap_or_else(|error| {
        panic!(
            "{error:#}; identity={:?}; current={:?}; target={:?}",
            crate::workflow_attempts::referenced_run_content_identity(
                root.path(),
                &["standalone-context".into()]
            ),
            crate::incremental_index::current_workspace_tree_hash(root.path()),
            PhaseTargetSnapshot::capture(root.path())
        );
    });
    let again = review(root.path(), input).unwrap();
    assert_eq!(first["data"], again["data"]);
    assert_eq!(first["data"]["mapOutcome"], "partial");
    let id = first["data"]["attemptId"].as_str().unwrap();
    let ledger = crate::workflow_attempts::load_phase_attempt_ledger(root.path()).unwrap();
    assert_eq!(ledger.attempts().count(), 1);
    assert!(ledger.attempt(id).unwrap().disposition.is_none());
    let selected = |acknowledged_partial| {
        crate::workflow_attempts::PhaseAttemptDispositionRecorded::new(
            id,
            crate::workflow_attempts::PhaseAttemptDisposition::Selected {
                acknowledged_partial,
            },
        )
    };
    let typed_path = crate::workflow_attempts::phase_attempt_v2_ledger_path(root.path());
    let before = std::fs::read(&typed_path).unwrap();
    assert!(
        crate::workflow_attempts::append_phase_attempt_disposition_v2_if_present(
            root.path(),
            &selected(false)
        )
        .is_err()
    );
    assert!(crate::workflow_attempts::append_phase_attempt_disposition(
        root.path(),
        selected(false)
    )
    .is_err());
    assert_eq!(std::fs::read(&typed_path).unwrap(), before);
    crate::workflow_attempts::append_phase_attempt_disposition(root.path(), selected(true))
        .unwrap();
    assert_eq!(
        crate::capabilities::threat_model::load_active_threat_model(root.path())
            .unwrap()
            .map(|model| model.model_ref),
        active
    );
    let config = V2Config {
        model: Some("openai-codex:gpt-5.5".into()),
        ..Default::default()
    };
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let draft = registry.execute_tool("campaign:study", json!({"campaignId":"next-study", "scanInput":{"taskMode":"manual","tasks":["secret-scan"]}}), &context(&workspace, &config, None)).unwrap();
    assert_eq!(
        draft["data"]["scanInput"]["threatModelRef"],
        json!(reference)
    );
    assert_eq!(draft["data"]["jobCount"], 3);
}

#[test]
fn source_drift_and_mixed_origins_are_refused_without_recording_acceptance() {
    let (root, reference) = fixture();
    for input in [
        json!({"threatModelRef":null}),
        json!({"threatModelRef":reference,"campaignId":"other"}),
        json!({"threatModelRef":reference,"expectedPlanSha256":"unreviewed"}),
    ] {
        assert!(review(root.path(), input).is_err());
    }
    std::fs::write(root.path().join("app.py"), "# changed source\n").unwrap();
    let error = review(root.path(), json!({"threatModelRef":reference})).unwrap_err();
    assert!(error.to_string().contains("source changed"), "{error:#}");
    assert_eq!(
        crate::workflow_attempts::load_phase_attempt_ledger(root.path())
            .unwrap()
            .attempts()
            .count(),
        0
    );
}

#[test]
fn corrupt_producing_result_never_becomes_a_map_result() {
    let (root, reference) = fixture();
    let path = run_dir(root.path(), "standalone-context").join("result.json");
    std::fs::write(path, "{}\n").unwrap();
    assert!(review(root.path(), json!({"threatModelRef":reference})).is_err());
    assert_eq!(
        crate::workflow_attempts::load_phase_attempt_ledger(root.path())
            .unwrap()
            .attempts()
            .count(),
        0
    );
}
