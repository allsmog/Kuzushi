use super::*;
use kuzushi_core::capabilities::threat_model::{
    commit_threat_model_revision, ScopeRef, ThreatModelCommit, ThreatModelRevisionSource,
};
use kuzushi_core::findings::{
    Finding, FindingStore, ReviewDecision, ReviewDecisionVerdict, Severity, TriageAuthor,
};

pub(super) fn prepare(
    target: &std::path::Path,
) -> (
    kuzushi_core::WorkspaceTarget,
    FindingStore,
    kuzushi_core::ThreatModelRef,
) {
    std::fs::create_dir_all(target).unwrap();
    std::fs::write(
        target.join("hello.txt"),
        "Owned greeting. Never executed.\n",
    )
    .unwrap();
    let workspace = kuzushi_core::WorkspaceTarget::new(target).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("lesson-observation", target, "run")
        .unwrap();
    store
        .insert_finding(
            "lesson-observation",
            &Finding::new_tool(
                "owned-fixture",
                "greeting",
                "hello.txt",
                1,
                None,
                Severity::Info,
                "Labeled greeting observation. No defect is claimed.",
            ),
        )
        .unwrap();
    store
        .record_run_finished("lesson-observation", "completed", 1)
        .unwrap();
    let id = store.list_all_findings().unwrap()[0].id.unwrap();
    store
        .append_user_review_decision(
            id,
            &ReviewDecision {
                verdict: ReviewDecisionVerdict::Confirmed,
                author: TriageAuthor::Human,
                confidence: 1.0,
                rationale: "Synthetic acceptance solely for lesson UI testing".into(),
                dismiss_reason: None,
                actor: Some("fixture operator".into()),
            },
        )
        .unwrap();
    let base=commit_threat_model_revision(target,&serde_json::json!({"version":"1","methodology":"stride","systemContext":"Owned greeting fixture","dfd":{"nodes":[{"id":"reader","name":"Greeting reader","type":"process","trustZone":"internal"}],"flows":[],"trustBoundaries":[]},"threats":[],"summary":{}}),ThreatModelCommit {model_id:None,new_model:true,label:"Owned lesson context".into(),scope:ScopeRef::legacy_root(target,&format!("sha256:{}","1".repeat(64))),methodology:"stride".into(),source:ThreatModelRevisionSource::Import,source_revision_id:None,run_id:None,activate:Some(true),actor:"lesson-fixture".into()}).unwrap().model_ref;
    (workspace, store, base)
}

#[test]
fn prepare_native_reviewed_lesson_fixture() {
    let Some(root) = std::env::var_os("KUZUSHI_LESSON_FIXTURE_OUT") else {
        return;
    };
    let root = PathBuf::from(root);
    let (workspace, store, base) = prepare(&root);
    let receipt = serde_json::json!({"findingId":store.list_all_findings().unwrap()[0].id,"baseRef":base,"findingsAreSynthetic":true,"providerRequests":0,"sourceExecuted":false});
    std::fs::write(
        workspace.root().join(".kuzushi/lesson-fixture.json"),
        serde_json::to_vec_pretty(&receipt).unwrap(),
    )
    .unwrap();
}
