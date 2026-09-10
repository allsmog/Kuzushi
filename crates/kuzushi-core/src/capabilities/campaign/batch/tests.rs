use super::*;

#[test]
fn batch_plan_is_dedicated_and_repeats_only_the_semantic_input() {
    let target = tempfile::tempdir().unwrap();
    std::fs::write(target.path().join("source.rs"), "fn main() {}\n").unwrap();
    let registry = ModuleRegistry::with_v2_builtins();
    let handle = compile_scan_batch_plan(ScanBatchPlanSpec {
        root: target.path(),
        batch_id: Some("batch-test".to_string()),
        trials: 3,
        requested_workers: 2,
        gate_policy: ScanBatchGatePolicy {
            fail_on: Some(crate::findings::Severity::High),
            sarif: Some(PathBuf::from("batch.sarif")),
        },
        prepared_input: json!({
            "runId": "discard", "triage": true, "verify": true, "autoPatch": true,
            "identityFold": "safe",
            "taskMode": "manual", "tasks": ["secret-scan"]
        }),
        config: &V2Config::default(),
        registry: &registry,
    })
    .unwrap();
    let plan: Value = serde_json::from_slice(&std::fs::read(handle.plan_path).unwrap()).unwrap();

    assert_eq!(plan["kind"], SCAN_BATCH_KIND);
    assert_eq!(plan["coverageBypassed"], true);
    assert_eq!(plan["fillGaps"], false);
    assert_eq!(plan["trialsPlanned"], 3);
    assert_eq!(plan["requestedWorkers"], 2);
    assert_eq!(plan["effectiveWorkers"], 2);
    assert_eq!(plan["workers"], 2);
    assert_eq!(plan["parallelSafety"]["safety"], "shared-read");
    assert_eq!(plan["gatePolicy"]["failOn"], "high");
    assert_eq!(plan["gatePolicy"]["sarif"], "batch.sarif");
    assert!(plan["baseInput"].get("runId").is_none());
    assert_eq!(plan["baseInput"]["triage"], false);
    assert_eq!(plan["baseInput"]["verify"], false);
    assert_eq!(plan["baseInput"]["autoPatch"], false);
    assert!(plan["baseInput"]["threatModelRef"].is_null());
    assert_eq!(plan["jobs"][0]["input"]["trial"], 1);
    assert_eq!(plan["jobs"][2]["input"]["trial"], 3);
    assert_eq!(plan["jobs"][0]["equivalenceKey"], plan["equivalenceKey"]);
    registry
        .prepare_tool_input("sast:scan", plan["jobs"][0]["input"].clone(), None)
        .expect("batch provenance keys must be descriptor-declared sast:scan options");
    validate_scan_batch_execution_plan("batch-test", &plan).unwrap();
}

#[test]
fn execution_plan_authentication_refuses_job_and_equivalence_tampering() {
    let target = tempfile::tempdir().unwrap();
    std::fs::write(target.path().join("source.rs"), "fn main() {}\n").unwrap();
    let registry = ModuleRegistry::with_v2_builtins();
    let handle = compile_scan_batch_plan(ScanBatchPlanSpec {
        root: target.path(),
        batch_id: Some("batch-auth".to_string()),
        trials: 2,
        requested_workers: 1,
        gate_policy: ScanBatchGatePolicy::default(),
        prepared_input: json!({
            "triage": false, "taskMode": "manual", "tasks": ["secret-scan"]
        }),
        config: &V2Config::default(),
        registry: &registry,
    })
    .unwrap();
    let plan: Value = serde_json::from_slice(&std::fs::read(handle.plan_path).unwrap()).unwrap();

    let mut duplicate = plan.clone();
    duplicate["jobs"][1] = duplicate["jobs"][0].clone();
    assert!(validate_scan_batch_execution_plan("batch-auth", &duplicate).is_err());
    let mut changed_tool = plan.clone();
    changed_tool["jobs"][0]["tool"] = json!("other:scan");
    assert!(validate_scan_batch_execution_plan("batch-auth", &changed_tool).is_err());
    let mut changed_input = plan.clone();
    changed_input["jobs"][0]["input"]["triage"] = json!(true);
    assert!(validate_scan_batch_execution_plan("batch-auth", &changed_input).is_err());
    let mut changed_receipt = plan;
    changed_receipt["equivalence"]["preparedInputSha256"] = json!("sha256:tampered");
    assert!(validate_scan_batch_execution_plan("batch-auth", &changed_receipt).is_err());

    let mut missing_receipt = changed_receipt;
    missing_receipt
        .as_object_mut()
        .unwrap()
        .remove("equivalence");
    assert!(validate_scan_batch_execution_plan("batch-auth", &missing_receipt).is_err());
}

#[test]
fn worktree_change_changes_the_equivalence_key() {
    let target = tempfile::tempdir().unwrap();
    let source = target.path().join("source.rs");
    std::fs::write(&source, "one\n").unwrap();
    let registry = ModuleRegistry::with_v2_builtins();
    let input = json!({"triage": false});
    let first =
        capture_batch_equivalence(target.path(), &input, &V2Config::default(), &registry).unwrap();
    std::fs::write(&source, "two\n").unwrap();
    let second =
        capture_batch_equivalence(target.path(), &input, &V2Config::default(), &registry).unwrap();
    assert_ne!(first.sha256, second.sha256);
    assert_ne!(
        first.components.workspace_identity,
        second.components.workspace_identity
    );
}

#[test]
fn child_consumption_attests_the_frozen_key_and_refuses_late_drift() {
    let target = tempfile::tempdir().unwrap();
    let source = target.path().join("source.rs");
    std::fs::write(&source, "one\n").unwrap();
    let registry = ModuleRegistry::with_v2_builtins();
    let handle = compile_scan_batch_plan(ScanBatchPlanSpec {
        root: target.path(),
        batch_id: Some("batch-child-drift".to_string()),
        trials: 2,
        requested_workers: 1,
        gate_policy: ScanBatchGatePolicy::default(),
        prepared_input: json!({
            "triage": false, "taskMode": "manual", "tasks": ["secret-scan"]
        }),
        config: &V2Config::default(),
        registry: &registry,
    })
    .unwrap();
    let plan: Value = serde_json::from_slice(&std::fs::read(handle.plan_path).unwrap()).unwrap();
    let input = plan["jobs"][0]["input"].clone();

    let receipt = verify_scan_batch_child_equivalence(
        target.path(),
        "batch-child-drift-trial-001-a1",
        &input,
        &V2Config::default(),
        &registry,
    )
    .unwrap()
    .unwrap();
    assert_eq!(receipt.expected_key, handle.equivalence_key.sha256);
    assert_eq!(receipt.consumed, handle.equivalence_key);

    std::fs::write(source, "two\n").unwrap();
    let error = verify_scan_batch_child_equivalence(
        target.path(),
        "batch-child-drift-trial-001-a2",
        &input,
        &V2Config::default(),
        &registry,
    )
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("child refused BatchEquivalenceKey drift"),
        "{error}"
    );
}

#[test]
fn project_decomposition_change_changes_the_equivalence_key() {
    let target = tempfile::tempdir().unwrap();
    let registry = ModuleRegistry::with_v2_builtins();
    let input = json!({
        "taskMode": "manual", "tasks": ["secret-scan"], "triage": false
    });
    let first =
        capture_batch_equivalence(target.path(), &input, &V2Config::default(), &registry).unwrap();
    let tree = crate::workspace::discover_nested_project_scopes(target.path());
    crate::workspace::save_nested_project_scopes(target.path(), &tree).unwrap();
    let second =
        capture_batch_equivalence(target.path(), &input, &V2Config::default(), &registry).unwrap();

    assert_ne!(
        first.components.scope_sha256,
        second.components.scope_sha256
    );
    assert_ne!(first.sha256, second.sha256);
}

#[test]
fn cpg_cache_change_changes_the_engine_identity() {
    let target = tempfile::tempdir().unwrap();
    let registry = ModuleRegistry::with_v2_builtins();
    let input = json!({
        "taskMode": "manual", "tasks": ["taint-iris-next"], "backend": "cpg-rs"
    });
    let first =
        capture_batch_equivalence(target.path(), &input, &V2Config::default(), &registry).unwrap();
    let artifact = kuzushi_cpg::artifact_dir(target.path()).join("rust.v-test.cpg");
    std::fs::create_dir_all(artifact.parent().unwrap()).unwrap();
    std::fs::write(artifact, b"graph-cache-v1").unwrap();
    let second =
        capture_batch_equivalence(target.path(), &input, &V2Config::default(), &registry).unwrap();

    assert_ne!(
        first.components.engine_identity.cache_identity,
        second.components.engine_identity.cache_identity
    );
    assert_ne!(first.sha256, second.sha256);
}

#[test]
fn runtime_backend_provider_and_config_are_explicit_equivalence_inputs() {
    let target = tempfile::tempdir().unwrap();
    let registry = ModuleRegistry::with_v2_builtins();
    let mut config = V2Config::default();
    config.model = Some("openai:gpt-test".to_string());
    let input = json!({"taskMode": "manual", "tasks": ["agentic-sast"]});
    let first = capture_batch_equivalence(target.path(), &input, &config, &registry).unwrap();
    assert_eq!(first.components.runtime_identity.backend, "lang-graph");
    assert_eq!(
        first.components.runtime_identity.provider.as_deref(),
        Some("openai")
    );
    config.runtime.base_url = Some("https://runtime.example.invalid".to_string());
    let second = capture_batch_equivalence(target.path(), &input, &config, &registry).unwrap();
    assert_ne!(
        first.components.runtime_identity.config_sha256,
        second.components.runtime_identity.config_sha256
    );
    assert_ne!(first.sha256, second.sha256);
}

#[test]
fn trial_count_is_bounded() {
    assert!(validate_trial_count(1).is_err());
    assert!(validate_trial_count(MAX_SCAN_BATCH_TRIALS + 1).is_err());
    assert!(validate_trial_count(2).is_ok());
}

#[test]
fn an_existing_batch_plan_is_never_overwritten() {
    let target = tempfile::tempdir().unwrap();
    let registry = ModuleRegistry::with_v2_builtins();
    let compile = || {
        compile_scan_batch_plan(ScanBatchPlanSpec {
            root: target.path(),
            batch_id: Some("batch-immutable".to_string()),
            trials: 2,
            requested_workers: 1,
            gate_policy: ScanBatchGatePolicy::default(),
            prepared_input: json!({"triage": false}),
            config: &V2Config::default(),
            registry: &registry,
        })
    };
    let handle = compile().unwrap();
    let first = std::fs::read(&handle.plan_path).unwrap();
    assert!(compile().is_err());
    assert_eq!(std::fs::read(&handle.plan_path).unwrap(), first);
}

#[test]
fn active_model_switch_keeps_the_batch_bound_to_its_immutable_revision() {
    let target = tempfile::tempdir().unwrap();
    let registry = ModuleRegistry::with_v2_builtins();
    let first_ref = commit_active_model(target.path(), "first");
    let handle = compile_scan_batch_plan(ScanBatchPlanSpec {
        root: target.path(),
        batch_id: Some("batch-model-binding".to_string()),
        trials: 2,
        requested_workers: 1,
        gate_policy: ScanBatchGatePolicy::default(),
        prepared_input: json!({"triage": false}),
        config: &V2Config::default(),
        registry: &registry,
    })
    .unwrap();
    let plan: Value = serde_json::from_slice(&std::fs::read(&handle.plan_path).unwrap()).unwrap();
    assert_eq!(plan["baseInput"]["threatModelRef"], json!(first_ref));
    commit_active_model(target.path(), "second");
    let current = capture_batch_equivalence(
        target.path(),
        &plan["baseInput"],
        &V2Config::default(),
        &registry,
    )
    .unwrap();
    assert_eq!(current.sha256, handle.equivalence_key.sha256);
    assert!(
        crate::capabilities::threat_model::acquire_exact_threat_model_read_lease(
            target.path(),
            Some(&first_ref)
        )
        .is_ok()
    );
}

#[test]
fn compilation_preserves_an_explicit_revision_or_omission_instead_of_the_active_model() {
    let target = tempfile::tempdir().unwrap();
    let registry = ModuleRegistry::with_v2_builtins();
    let first = commit_active_model(target.path(), "first");
    let second = commit_active_model(target.path(), "second");
    for (id, selection) in [("selected", json!(first)), ("omitted", Value::Null)] {
        let handle = compile_scan_batch_plan(ScanBatchPlanSpec {
            root: target.path(), batch_id: Some(format!("batch-{id}")), trials: 3,
            requested_workers: 1, gate_policy: ScanBatchGatePolicy::default(),
            prepared_input: json!({"threat_model_ref": selection, "triage": false}),
            config: &V2Config::default(), registry: &registry,
        }).unwrap();
        let plan: Value = serde_json::from_slice(&std::fs::read(handle.plan_path).unwrap()).unwrap();
        assert_eq!(plan["baseInput"]["threatModelRef"], selection);
        assert!(plan["baseInput"].get("threat_model_ref").is_none());
    }
    assert_eq!(crate::capabilities::threat_model::load_active_threat_model(target.path()).unwrap().unwrap().model_ref, second);
}

#[test]
fn controller_lease_allows_activation_while_preserving_the_bound_revision() {
    let target = tempfile::tempdir().unwrap();
    let registry = ModuleRegistry::with_v2_builtins();
    commit_active_model(target.path(), "first");
    let handle = compile_scan_batch_plan(ScanBatchPlanSpec {
        root: target.path(),
        batch_id: Some("batch-model-lease".to_string()),
        trials: 2,
        requested_workers: 1,
        gate_policy: ScanBatchGatePolicy::default(),
        prepared_input: json!({"triage": false}),
        config: &V2Config::default(),
        registry: &registry,
    })
    .unwrap();
    let plan: Value = serde_json::from_slice(&std::fs::read(handle.plan_path).unwrap()).unwrap();
    let validated = validate_scan_batch_execution_plan("batch-model-lease", &plan).unwrap();
    let lease = acquire_scan_batch_threat_model_lease(target.path(), &validated).unwrap();
    let root = target.path().to_path_buf();
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        let activated = commit_active_model(&root, "second");
        done_tx.send(activated).unwrap();
    });

    started_rx.recv().unwrap();
    let activated = done_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("a bound revision must not block changing the active model");
    drop(lease);
    worker.join().unwrap();
    let active = crate::capabilities::threat_model::load_active_threat_model(target.path())
        .unwrap()
        .unwrap();
    assert_eq!(active.model_ref, activated);
}

fn commit_active_model(
    root: &Path,
    label: &str,
) -> crate::capabilities::threat_model::ThreatModelRef {
    use crate::capabilities::threat_model::{
        ScopeRef, ThreatModelCommit, ThreatModelRevisionSource,
    };
    crate::capabilities::threat_model::commit_threat_model_revision(
        root,
        &json!({
            "version": "1",
            "methodology": "stride",
            "title": label,
            "dfd": {
                "nodes": [{
                    "id": "workspace",
                    "type": "process",
                    "name": "Workspace",
                    "description": "Batch test target",
                    "trustZone": "internal"
                }],
                "flows": [],
                "trustBoundaries": []
            },
            "threats": [],
            "summary": {}
        }),
        ThreatModelCommit {
            model_id: None,
            new_model: true,
            label: label.to_string(),
            scope: ScopeRef::legacy_root(root, &format!("sha256:{}", "1".repeat(64))),
            methodology: "stride".to_string(),
            source: ThreatModelRevisionSource::Build,
            source_revision_id: None,
            run_id: None,
            activate: Some(true),
            actor: "batch-test".to_string(),
        },
    )
    .unwrap()
    .model_ref
}
