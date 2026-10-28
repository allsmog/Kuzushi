use super::*;
use crate::capabilities::threat_model::{
    commit_threat_model_revision, ScopeRef, ThreatModelCommit, ThreatModelRevisionSource,
};

#[test]
#[ignore = "Explicit owned native fixture preparation only"]
fn prepare_native_historical_lesson_fixture() {
    let root = std::path::PathBuf::from(
        std::env::var_os("KUZUSHI_LESSON_SUPPORT_FIXTURE_OUT")
            .expect("Select an owned temporary fixture path"),
    );
    std::fs::create_dir_all(&root).unwrap();
    let root = root.canonicalize().unwrap();
    let artifacts = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/devex/artifacts")
        .canonicalize()
        .unwrap();
    assert!(
        root.starts_with(std::env::temp_dir().canonicalize().unwrap())
            || root.starts_with(artifacts)
    );
    let workspace = WorkspaceTarget::new(&root).unwrap();
    assert!(
        !workspace.findings_db_path().exists(),
        "Never overwrite a prior fixture ledger"
    );
    std::fs::write(root.join("hello.txt"), "Owned greeting. Never executed.\n").unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let finding = Finding::new_tool(
        "owned-fixture",
        "greeting",
        "hello.txt",
        1,
        None,
        Severity::Info,
        "Labeled synthetic greeting observation. No defect is claimed.",
    );
    store
        .with_run_lifecycle("lesson-observation", &root, || {
            insert_recorded_finding(&store, &workspace, "lesson-observation", &finding)?;
            Ok(((), 1))
        })
        .unwrap();
    let id = store.list_all_findings().unwrap()[0].id.unwrap();
    store
        .append_user_review_decision(
            id,
            &ReviewDecision {
                verdict: ReviewDecisionVerdict::Confirmed,
                author: TriageAuthor::Human,
                confidence: 1.0,
                rationale: "Synthetic confirmation solely for historical source selection testing"
                    .into(),
                dismiss_reason: None,
                actor: Some("fixture operator".into()),
            },
        )
        .unwrap();
    let base = commit_threat_model_revision(&root, &json!({"version":"1","methodology":"stride","systemContext":"Owned greeting fixture, manually declared architecture","dfd":{"nodes":[{"id":"reader","name":"Greeting reader","type":"process","trustZone":"internal"}],"flows":[],"trustBoundaries":[]},"threats":[],"summary":{}}), ThreatModelCommit { model_id: None, new_model: true, label: "Owned lesson context".into(), scope: ScopeRef::legacy_root(&root, &format!("sha256:{}", "1".repeat(64))), methodology: "stride".into(), source: ThreatModelRevisionSource::Import, source_revision_id: None, run_id: None, activate: Some(true), actor: "fixture operator".into() }).unwrap().model_ref;
    std::fs::write(root.join(".kuzushi/lesson-fixture.json"), serde_json::to_vec_pretty(&json!({"findingId":id,"baseRef":base,"findingsAreSynthetic":true,"providerRequests":0,"sourceExecuted":false})).unwrap()).unwrap();
}
