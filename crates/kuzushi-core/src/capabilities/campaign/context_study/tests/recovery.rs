use super::*;
use crate::capabilities::threat_model::{
    commit_threat_model_revision, ScopeRef, ThreatModelCommit, ThreatModelRevisionSource,
};

#[test]
fn unfinished_context_has_no_result_but_completed_missing_output_is_an_error() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("main.rs"), "fn main() {}\n").unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config { model: Some(MODEL.into()), ..Default::default() };
    draft(&ModuleRegistry::with_v2_builtins(), &context(&workspace, &config), json!({})).unwrap();
    let receipt = load_context_study(root.path(), "context-draft").unwrap();
    assert_eq!(receipt.generated_context(root.path()).unwrap(), None);
    for state in ["running", "failed", "interrupted"] {
        queue(root.path(), state, Some("expected-run"));
        assert_eq!(receipt.generated_context(root.path()).unwrap(), None);
    }
    queue(root.path(), "completed", None);
    assert_error(&receipt, root.path(), "no run identity");
    queue(root.path(), "completed", Some("expected-run"));
    assert_error(&receipt, root.path(), "no immutable context manifest");
    commit(root.path(), "unrelated-run");
    assert_error(&receipt, root.path(), "no immutable revision for run expected-run");
    let reference = commit(root.path(), "expected-run");
    assert_eq!(receipt.generated_context(root.path()).unwrap(), Some(reference));
    commit(root.path(), "expected-run");
    assert_error(&receipt, root.path(), "ambiguous immutable revisions");
}

fn assert_error(receipt: &ContextStudyReceipt, root: &Path, expected: &str) {
    let error = receipt.generated_context(root).unwrap_err();
    assert!(format!("{error:#}").contains(expected), "{error:#}");
}

fn queue(root: &Path, state: &str, run: Option<&str>) {
    write_json_atomic(&campaign_queue_path(root, "context-draft"),
        &json!({"jobs":{"context-001":{"state":state,"runId":run}}})).unwrap();
}

fn commit(root: &Path, run: &str) -> crate::ThreatModelRef {
    commit_threat_model_revision(root, &json!({"version":"1", "methodology":"stride", "title":"Labeled recovery fixture", "dfd":{"nodes":[],"flows":[],"trustBoundaries":[]},"threats":[],"summary":{}}),
        ThreatModelCommit {
            model_id: None, new_model: true, label: "Recovery fixture".into(),
            scope: ScopeRef::legacy_root(root, &format!("sha256:{}", "1".repeat(64))),
            methodology: "stride".into(), source: ThreatModelRevisionSource::Import,
            source_revision_id: None, run_id: Some(run.into()), activate: Some(false), actor: "test".into(),
        }).unwrap().model_ref
}
