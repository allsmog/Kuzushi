mod support;
use crate::{
    modules::{AllowanceCategory, ModuleMaturity},
    ModuleRegistry,
};
use serde_json::json;
use support::*;

#[test]
fn hypotheses_are_experimental_discovery_without_review_checkpoint_ownership() {
    let registry = ModuleRegistry::with_v2_builtins();
    let tool = registry.resolve_tool("triage:chain-hunt").unwrap();
    assert_eq!(tool.discovery_maturity, Some(ModuleMaturity::Labs));
    assert!(!tool.phase_result);
    assert_eq!(tool.allowance_category, Some(AllowanceCategory::Discovery));
    assert!(!registry.tool_is_discoverable(&tool.name));
    for input in [
        json!({"maxChains":33}),
        json!({"maxCandidates":1}),
        json!({"maxOutputTokens":0}),
        json!({"scanContextRef":{}}),
    ] {
        assert!(registry
            .prepare_tool_input(&tool.name, input, None)
            .is_err());
    }
}

#[test]
fn real_prepared_dispatch_publishes_only_an_unreviewed_metadata_hypothesis() {
    let fixture = Fixture::new(3);
    let before = fixture.store.list_all_review_decisions().unwrap();
    let result = fixture.dispatch(json!({})).unwrap();
    assert_eq!(result["status"], "completed");
    assert_eq!(result["data"]["relationshipsVerified"], false);
    assert_eq!(result["data"]["sourceRevisionVerified"], false);
    assert_eq!(fixture.query_count(), 1);
    assert_eq!(fixture.store.list_all_review_decisions().unwrap(), before);
    let findings = fixture.store.list_all_findings().unwrap();
    assert_eq!(findings.len(), 3);
    let hypothesis = findings.iter().find(|f| f.tool == "chains").unwrap();
    assert!(matches!(
        crate::findings::load_finding_review_gate(&fixture.store, hypothesis).unwrap(),
        crate::findings::FindingReviewGate::Unreviewed
    ));
    let requests = fixture.runtime.requests.lock().unwrap();
    let request = &requests[0];
    assert!(request.tool_policy.tools.is_empty());
    assert!(!request.tool_policy.mcps);
    assert!(!request.tool_policy.is_default());
    assert_eq!(request.thinking_level, None);
    assert_eq!(request.max_output_tokens, Some(4096));
    assert_eq!(
        request.runtime_options.as_ref().unwrap().max_model_turns,
        Some(1)
    );
}

#[test]
fn optional_hypotheses_cannot_borrow_protected_review_calls() {
    let fixture = Fixture::new(1);
    assert!(fixture.dispatch(json!({})).is_err());
    assert_eq!(fixture.query_count(), 0);
    assert_eq!(fixture.store.list_all_findings().unwrap().len(), 2);
}

#[test]
fn malformed_output_has_only_one_budgeted_repair_and_no_findings() {
    let mut fixture = Fixture::new(3);
    fixture.runtime.response = json!({});
    assert!(fixture.dispatch(json!({})).is_err());
    assert_eq!(fixture.query_count(), 2);
    assert_eq!(fixture.store.list_all_findings().unwrap().len(), 2);
}

#[test]
fn canceled_model_output_does_not_create_a_hypothesis() {
    let mut fixture = Fixture::new(3);
    fixture.runtime.cancel_after_response = Some(fixture.cancellation.clone());
    assert!(fixture.dispatch(json!({})).is_err());
    assert_eq!(fixture.query_count(), 1);
    assert_eq!(fixture.store.list_all_findings().unwrap().len(), 2);
}

#[test]
fn a_changed_member_confirmation_prevents_publication() {
    let mut fixture = Fixture::new(3);
    let member = fixture.store.list_all_findings().unwrap()[0].id.unwrap();
    fixture.runtime.dismiss_after_response = Some((fixture.workspace.findings_db_path(), member));
    let error = fixture.dispatch(json!({})).unwrap_err();
    assert!(error.to_string().contains("no longer confirmed"));
    assert_eq!(fixture.query_count(), 1);
    assert_eq!(fixture.store.list_all_findings().unwrap().len(), 2);
}

#[test]
fn metadata_bytes_are_bounded_before_any_model_request() {
    let fixture = Fixture::new(3);
    fixture
        .store
        .record_run_started("large-metadata", fixture.workspace.root(), "running")
        .unwrap();
    let finding = crate::findings::Finding::new_tool(
        "owned-metadata",
        "large",
        format!("{}.txt", "a".repeat(512)),
        1,
        None,
        crate::findings::Severity::Info,
        "Labeled owned metadata ".repeat(40),
    );
    let id = fixture
        .store
        .insert_finding("large-metadata", &finding)
        .unwrap();
    confirm(&fixture.store, id);
    let error = fixture
        .dispatch(json!({"maxContextBytes":1024}))
        .unwrap_err();
    assert!(error.to_string().contains("metadata prompt exceeds"));
    assert_eq!(fixture.query_count(), 0);
}

#[test]
fn omitted_metadata_is_disclosed_instead_of_complete_coverage() {
    let mut fixture = Fixture::new(3);
    append_owned_finding(&fixture.store, &fixture.workspace, "third", true);
    fixture.runtime.response = json!({"chains":[]});
    let result = fixture.dispatch(json!({"max_candidates":2})).unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(result["data"]["inputCoverage"]["eligibleConfirmed"], 3);
    assert_eq!(result["data"]["inputCoverage"]["suppliedConfirmed"], 2);
}

#[test]
fn confirmed_composite_findings_do_not_become_recursive_inputs() {
    let fixture = Fixture::new(4);
    fixture.dispatch(json!({})).unwrap();
    let hypothesis = fixture
        .store
        .list_all_findings()
        .unwrap()
        .into_iter()
        .find(|f| f.tool == "chains")
        .unwrap();
    confirm(&fixture.store, hypothesis.id.unwrap());
    let result = fixture.dispatch(json!({})).unwrap();
    assert_eq!(result["data"]["inputCoverage"]["eligibleConfirmed"], 2);
    assert_eq!(result["data"]["inputCoverage"]["priorHypotheses"], 1);
}

#[test]
fn prepare_native_chain_hypothesis_fixture() {
    let fixture = Fixture::new(3);
    assert_eq!(fixture.store.list_all_findings().unwrap().len(), 2);
    let Ok(path) = std::env::var("KUZUSHI_CHAIN_FIXTURE_ROOT") else {
        return;
    };
    let root = std::path::PathBuf::from(path);
    let receipt: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join(".kuzushi/lesson-fixture.json")).unwrap())
            .unwrap();
    assert_eq!(receipt["findingsAreSynthetic"], true);
    let workspace = crate::WorkspaceTarget::new(&root).unwrap();
    let store = crate::findings::FindingStore::open(workspace.findings_db_path()).unwrap();
    assert_eq!(store.list_all_findings().unwrap().len(), 1);
    append_owned_finding(&store, &workspace, "second", true);
    std::fs::write(
        root.join("second.txt"),
        "Owned secondary greeting. Never executed.\n",
    )
    .unwrap();
    let members = store
        .list_all_findings()
        .unwrap()
        .into_iter()
        .map(|f| f.fingerprint)
        .collect::<Vec<_>>();
    std::fs::write(
        root.join(".kuzushi/chain-fixture.json"),
        serde_json::to_vec(&json!({
        "memberFingerprints":members,"findingsAreSynthetic":true,"providerRequests":0}))
        .unwrap(),
    )
    .unwrap();
}
