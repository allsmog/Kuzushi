use super::*;
use crate::modules::ModuleRegistry;
use crate::V2Config;

fn fixture() -> (tempfile::TempDir, ScanResourceEvidence) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("app.py"),
        "print('Labeled source fixture')\n",
    )
    .unwrap();
    let config = V2Config {
        model: Some("openai-codex:gpt-5.5".into()),
        ..Default::default()
    };
    let key = capture_batch_equivalence(
        root.path(),
        &serde_json::json!({"threatModelRef":null,"taskMode":"manual","tasks":["agentic-sast"]}),
        &config,
        &ModuleRegistry::with_v2_builtins(),
    )
    .unwrap();
    let evidence = ScanResourceEvidence {
        run_id: "labeled-completed-scan".into(),
        cost_usd: None,
        provider_usage: Some(ProviderRunUsage {
            run_id: "labeled-completed-scan".into(),
            investigation_id: "labeled-study".into(),
            model: "openai-codex:gpt-5.5".into(),
            tool: "sast:scan".into(),
            source_identity: key.components.workspace_identity.clone(),
            config_sha256: key.components.config_sha256.clone(),
            committed_calls: 4,
            unresolved_calls: 0,
        }),
        equivalence: Some(key),
        calibration_limitation: None,
    };
    (root, evidence)
}

#[test]
fn matched_conditions_project_request_workload_without_inventing_dollars() {
    let (_root, mut evidence) = fixture();
    let key = evidence.equivalence.as_ref().unwrap();
    assert_eq!(
        evidence.project(key, 3, 1).unwrap(),
        StudyResourceProjection {
            provider_calls: Some(12),
            cost_usd: None,
            starts: 3
        }
    );
    assert_eq!(
        evidence.project(key, 3, 2).unwrap().provider_calls,
        Some(24)
    );
    evidence.cost_usd = Some(0.25);
    assert_eq!(
        evidence
            .project(evidence.equivalence.as_ref().unwrap(), 3, 2)
            .unwrap()
            .cost_usd,
        Some(1.5)
    );
}

#[test]
fn changed_revision_context_model_runtime_or_options_withholds_projection() {
    let (_root, evidence) = fixture();
    for field in ["source", "context", "model", "runtime", "options"] {
        let mut current = evidence.equivalence.as_ref().unwrap().clone();
        match field {
            "source" => current.components.workspace_identity = "another-source".into(),
            "context" => current.components.threat_model = Some(serde_json::json!({"revision":2})),
            "model" => current.components.model = Some("operator:other-model".into()),
            "runtime" => current.components.runtime_identity.backend = "other-runtime".into(),
            _ => current.components.prepared_input_sha256 = "other-options".into(),
        }
        assert!(evidence.project(&current, 3, 1).is_err(), "{field}");
    }
}

#[test]
fn missing_accounting_unresolved_calls_and_incomplete_engine_work_never_look_free() {
    let (_root, mut evidence) = fixture();
    let key = evidence.equivalence.clone().unwrap();
    evidence.provider_usage.as_mut().unwrap().unresolved_calls = 1;
    assert!(evidence.project(&key, 3, 1).is_err());
    evidence.provider_usage = None;
    assert_eq!(evidence.project(&key, 3, 1).unwrap().provider_calls, None);
    evidence.calibration_limitation = Some("partial engine work".into());
    assert!(evidence.project(&key, 3, 1).is_err());
    evidence.calibration_limitation = None;
    evidence.equivalence = None;
    assert!(evidence.project(&key, 3, 1).is_err());
}

#[test]
fn workload_bounds_and_ledger_identity_are_checked_before_calibration() {
    let (_root, mut evidence) = fixture();
    let key = evidence.equivalence.clone().unwrap();
    for (passes, attempts) in [(0, 1), (101, 1), (3, 0), (3, 11)] {
        assert!(evidence.project(&key, passes, attempts).is_err());
    }
    for field in ["tool", "source", "config", "model"] {
        let mut usage = evidence.provider_usage.clone().unwrap();
        match field {
            "tool" => usage.tool = "other:tool".into(),
            "source" => usage.source_identity = "other-source".into(),
            "config" => usage.config_sha256 = "other-config".into(),
            _ => usage.model = "operator:other-model".into(),
        }
        assert!(
            validate_usage_identity(Some(&usage), Some(&key)).is_err(),
            "{field}"
        );
    }
    evidence.provider_usage.as_mut().unwrap().committed_calls = 0;
    assert_eq!(
        evidence.project(&key, 3, 1).unwrap().provider_calls,
        Some(0)
    );
}

#[test]
fn legacy_known_money_remains_historical_without_completion_or_condition_receipts() {
    let root = tempfile::tempdir().unwrap();
    let summary = RunSummary::running(
        "legacy-completed",
        "tool",
        Some("sast:scan".into()),
        root.path().display().to_string(),
    )
    .complete()
    .with_cost(Some(0.25));
    let evidence = load_scan_resource_evidence(root.path(), &summary).unwrap();
    assert_eq!(evidence.cost_usd, Some(0.25));
    assert!(evidence.provider_usage.is_none() && evidence.equivalence.is_none());
    assert!(evidence
        .calibration_limitation
        .unwrap()
        .contains("completion receipt"));
    let mut unresolved = summary.clone();
    unresolved.provider_spend_unresolved = true;
    assert_eq!(
        load_scan_resource_evidence(root.path(), &unresolved)
            .unwrap()
            .cost_usd,
        None
    );
    assert!(load_scan_resource_evidence(root.path(), &summary.failed("labeled failure")).is_err());
}
