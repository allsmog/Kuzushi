use super::*;
use crate::capabilities::threat_model::{
    commit_threat_model_revision, ScopeRef, ThreatModelCommit, ThreatModelRevisionSource,
};

#[test]
fn evidence_context_recovery_authenticates_paths_parent_model_and_run() {
    let receipt:ContextStudyReceipt=serde_json::from_value(json!({"generationTool":"threat-model:build","campaignId":"draft",
        "investigationId":"investigation","planSha256":"digest","sourceIdentity":"source","configSha256":"config","model":MODEL,
        "input":{"sourcePaths":[" app /one.rs"],"inheritedContextRef":{"exact":"parent"}}})).unwrap();
    let document = json!({"provenance":{"fileContext":{"receipt":{"sourcePaths":[" app /one.rs"],
        "inheritedContextRef":{"exact":"parent"},"model":MODEL,"runId":"context-run"}}}});
    super::super::recovery::validate_generated_origin(&receipt, "context-run", &document).unwrap();
    for (key, value) in [
        ("sourcePaths", json!(["app/one.rs"])),
        ("inheritedContextRef", json!({"exact":"other"})),
        ("model", json!("another-model")),
        ("runId", json!("another-run")),
    ] {
        let mut changed = document.clone();
        changed["provenance"]["fileContext"]["receipt"][key] = value;
        assert!(
            super::super::recovery::validate_generated_origin(&receipt, "context-run", &changed)
                .is_err(),
            "{key}"
        );
    }
}

#[test]
fn regenerated_origin_must_match_frozen_parent_model_run_and_field_set() {
    let receipt = ContextStudyReceipt {
        brief_guidance: None,
        scope_study_origin: None,
        generation_tool: "threat-model:regenerate".into(),
        campaign_id: "draft".into(),
        investigation_id: "investigation".into(),
        plan_sha256: "digest".into(),
        source_identity: "source".into(),
        source_inventory: None,
        config_sha256: "config".into(),
        model: MODEL.into(),
        input: json!({"threatModelRef":{"exact":"parent"},"fields":["/systemContext"]}),
        preparation_jobs: Vec::new(),
    };
    let document = json!({"provenance":{"regeneration":{"sourceModelRef":receipt.input["threatModelRef"],
        "receipt":{"model":MODEL,"runId":"generated-run","selectedFields":["/systemContext"]}}}});
    super::super::recovery::validate_generated_origin(&receipt, "generated-run", &document)
        .unwrap();
    for (pointer, value) in [
        (
            "/provenance/regeneration/sourceModelRef",
            json!({"exact":"other-parent"}),
        ),
        (
            "/provenance/regeneration/receipt/model",
            json!("other-model"),
        ),
        ("/provenance/regeneration/receipt/runId", json!("other-run")),
        (
            "/provenance/regeneration/receipt/selectedFields",
            json!(["/dfd/nodes/0/purpose"]),
        ),
    ] {
        let mut changed = document.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(
            super::super::recovery::validate_generated_origin(&receipt, "generated-run", &changed)
                .is_err(),
            "{pointer}"
        );
    }
}

#[test]
fn unfinished_context_has_no_result_but_completed_missing_output_is_an_error() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("main.rs"), "fn main() {}\n").unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config {
        model: Some(MODEL.into()),
        ..Default::default()
    };
    draft(
        &ModuleRegistry::with_v2_builtins(),
        &context(&workspace, &config),
        json!({}),
    )
    .unwrap();
    let receipt = load_context_study(root.path(), "context-draft").unwrap();
    assert_eq!(receipt.generated_context(root.path()).unwrap(), None);
    for state in ["planned", "running"] {
        queue(root.path(), state, Some("expected-run"));
        assert_eq!(receipt.generated_context(root.path()).unwrap(), None);
    }
    for state in ["failed", "interrupted", "parked", "partial", "unrecognized"] {
        queue(root.path(), state, Some("expected-run"));
        assert_error(&receipt, root.path(), &format!("is {state}"));
    }
    queue(root.path(), "completed", None);
    assert_error(&receipt, root.path(), "no run identity");
    queue(root.path(), "completed", Some("expected-run"));
    assert_error(&receipt, root.path(), "no immutable context manifest");
    commit(root.path(), "unrelated-run");
    assert_error(
        &receipt,
        root.path(),
        "no immutable revision for run expected-run",
    );
    let reference = commit(root.path(), "expected-run");
    assert_eq!(
        receipt.generated_context(root.path()).unwrap(),
        Some(reference.clone())
    );
    let output = receipt
        .generated_context_document(root.path())
        .unwrap()
        .unwrap();
    assert_eq!(output.reference, reference);
    assert_eq!(
        output.document,
        crate::capabilities::threat_model::load_exact_threat_model(root.path(), &reference)
            .unwrap()
    );
    commit(root.path(), "expected-run");
    assert_error(&receipt, root.path(), "ambiguous immutable revisions");
}

fn assert_error(receipt: &ContextStudyReceipt, root: &Path, expected: &str) {
    let error = receipt.generated_context(root).unwrap_err();
    assert!(format!("{error:#}").contains(expected), "{error:#}");
}

fn queue(root: &Path, state: &str, run: Option<&str>) {
    write_json_atomic(
        &campaign_queue_path(root, "context-draft"),
        &json!({"jobs":{"context-001":{"state":state,"runId":run}}}),
    )
    .unwrap();
}

fn commit(root: &Path, run: &str) -> crate::ThreatModelRef {
    commit_threat_model_revision(root, &json!({"version":"1", "methodology":"stride", "title":"Labeled recovery fixture", "dfd":{"nodes":[{"id":"app","type":"process","name":"Recovery fixture","trustZone":"internal"}],"flows":[],"trustBoundaries":[]},"threats":[],"summary":{}}),
        ThreatModelCommit {
            model_id: None, new_model: true, label: "Recovery fixture".into(),
            scope: ScopeRef::legacy_root(root, &format!("sha256:{}", "1".repeat(64))),
            methodology: "stride".into(), source: ThreatModelRevisionSource::Import,
            source_revision_id: None, run_id: Some(run.into()), activate: Some(false), actor: "test".into(),
        }).unwrap().model_ref
}
