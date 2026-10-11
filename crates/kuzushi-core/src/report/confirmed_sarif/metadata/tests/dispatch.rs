use crate::findings::{
    Finding, FindingStore, ReviewDecision, ReviewDecisionVerdict, Severity, TriageAuthor,
};
use crate::modules::{ModuleRegistry, ToolExecutionContext};
use crate::{V2Config, WorkspaceTarget};
use serde_json::{json, Value};
use std::fs;

fn confirm(store: &FindingStore, id: i64) {
    store
        .append_user_review_decision(
            id,
            &ReviewDecision {
                verdict: ReviewDecisionVerdict::Confirmed,
                author: TriageAuthor::Human,
                confidence: 0.8,
                rationale: "Labeled source-metadata decision".into(),
                dismiss_reason: None,
                actor: Some("operator".into()),
            },
        )
        .unwrap();
}

fn export(workspace: &WorkspaceTarget, store: &FindingStore, input: Value) -> Value {
    let config = V2Config::default();
    let registry = ModuleRegistry::with_v2_builtins();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(workspace),
        findings_store: Some(store),
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let prepared = registry
        .prepare_dispatch_input("report:sarif", input, &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    let result = registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap();
    serde_json::from_slice(&fs::read(result["data"]["path"].as_str().unwrap()).unwrap()).unwrap()
}

#[test]
fn shared_sarif_keeps_confirmation_and_discloses_changed_cited_source() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("main.rs");
    fs::write(&path, "// Owned source Alpha.\n").unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let finding = Finding::new_tool(
        "owned-fixture",
        "owned.marker",
        "main.rs",
        1,
        None,
        Severity::Low,
        "Labeled observation, no security claim",
    );
    store
        .record_run_started("run-alpha", root.path(), "running")
        .unwrap();
    let id = store.insert_finding("run-alpha", &finding).unwrap();
    confirm(&store, id);
    fs::write(&path, "// Owned source Beta.\n").unwrap();
    store
        .record_run_started("run-beta", root.path(), "running")
        .unwrap();
    store.insert_finding("run-beta", &finding).unwrap();
    let before = serde_json::to_value(store.list_all_findings().unwrap()).unwrap();
    let document = export(&workspace, &store, json!({"output":"owned-history.sarif"}));
    assert_eq!(document["runs"][0]["results"].as_array().unwrap().len(), 1);
    let properties = &document["runs"][0]["results"][0]["properties"];
    assert_eq!(properties["kuzushiReviewDecision"], "confirmed");
    assert_eq!(properties["kuzushiReviewDecisionAuthor"], "human");
    assert_eq!(
        properties["kuzushiReviewDecisionBasis"]["runId"],
        "run-alpha"
    );
    assert_eq!(
        properties["kuzushiReviewDecisionBasis"]["laterObservation"]["runId"],
        "run-beta"
    );
    assert_eq!(
        properties["kuzushiSourceApplicability"],
        "reassessment_required"
    );
    assert_eq!(
        properties["kuzushiCurrentCheckoutApplicability"],
        "not_assessed"
    );
    assert_eq!(
        serde_json::to_value(store.list_all_findings().unwrap()).unwrap(),
        before
    );
}

#[test]
fn unsupported_inputs_and_missing_context_refuse_before_writing() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config::default();
    let registry = ModuleRegistry::with_v2_builtins();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    assert!(registry
        .prepare_dispatch_input("report:sarif", json!({"unknown":1}), &ctx, None)
        .is_err());
    let prepared = registry
        .prepare_dispatch_input(
            "report:sarif",
            json!({"output":"must-not-exist.sarif"}),
            &ctx,
            None,
        )
        .unwrap()
        .authorize_explicit_headless();
    assert!(registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .is_err());
    assert!(!root.path().join("must-not-exist.sarif").exists());
}

#[test]
fn later_human_rejection_reverses_a_historical_confirmation() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let finding = Finding::new_semgrep(
        "owned.marker",
        "main.rs",
        1,
        None,
        Severity::Low,
        "Labeled observation",
    );
    store
        .record_run_started("alpha", root.path(), "completed")
        .unwrap();
    let first = store.insert_finding("alpha", &finding).unwrap();
    confirm(&store, first);
    store
        .record_run_started("beta", root.path(), "completed")
        .unwrap();
    let latest = store.insert_finding("beta", &finding).unwrap();
    store
        .append_user_review_decision(
            latest,
            &ReviewDecision {
                verdict: ReviewDecisionVerdict::RejectedFalsePositive,
                author: TriageAuthor::Human,
                confidence: 0.9,
                rationale: "Reversed labeled decision".into(),
                dismiss_reason: None,
                actor: Some("operator".into()),
            },
        )
        .unwrap();
    let document = export(&workspace, &store, json!({"output":"reversed.sarif"}));
    assert!(document["runs"][0]["results"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(store.list_all_review_decisions().unwrap().len(), 2);
}

#[test]
#[ignore = "explicit native TUI fixture preparation only"]
fn prepare_native_confirmed_sarif_fixture() {
    let root = std::path::PathBuf::from(std::env::var("KUZUSHI_SARIF_FIXTURE_OUT").unwrap());
    fs::create_dir_all(&root).unwrap();
    for name in ["app.py", "config.env"] {
        let _ = fs::remove_file(root.join(name));
    }
    let path = root.join("main.rs");
    fs::write(&path, "// Owned source Alpha; not executed.\n").unwrap();
    let workspace = WorkspaceTarget::new(&root).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let finding = Finding::new_tool(
        "owned-fixture",
        "owned.marker",
        "main.rs",
        1,
        None,
        Severity::Low,
        "Labeled observation, no security claim",
    );
    store
        .record_run_started("owned-alpha", &root, "completed")
        .unwrap();
    let id = store.insert_finding("owned-alpha", &finding).unwrap();
    confirm(&store, id);
    fs::write(&path, "// Owned source Beta; not executed.\n").unwrap();
    store
        .record_run_started("owned-beta", &root, "completed")
        .unwrap();
    store.insert_finding("owned-beta", &finding).unwrap();
    let current = store.list_all_findings().unwrap();
    fs::write(root.join(".kuzushi/sarif-fixture.json"), json!({"findingsAreSynthetic":true,"observations":2,"findingId":current[0].id,"fingerprint":current[0].fingerprint,"providerRequests":0,"sourceExecuted":false}).to_string()).unwrap();
}
