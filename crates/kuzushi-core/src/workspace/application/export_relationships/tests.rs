use super::*;
use crate::findings::{FindingRelationshipKind, FindingRelationshipState, Severity};

#[test]
fn exports_include_removed_relationships_without_converting_them_to_finding_verdicts() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("owned-fixture", workspace.root(), "completed")
        .unwrap();
    for rule in ["a", "b"] {
        store
            .insert_finding(
                "owned-fixture",
                &Finding::new_tool(
                    "owned-fixture",
                    rule,
                    "hello.txt",
                    1,
                    None,
                    Severity::Info,
                    "Labeled observation",
                ),
            )
            .unwrap();
    }
    let findings = store.list_all_findings().unwrap();
    let proposal = store
        .propose_finding_relationship(
            findings[0].id.unwrap(),
            findings[1].id.unwrap(),
            FindingRelationshipKind::Duplicate,
            "Labeled proposal",
            None,
        )
        .unwrap();
    store
        .review_finding_relationship(
            &proposal.id,
            FindingRelationshipState::Removed,
            "Keep separate after review",
            1,
        )
        .unwrap();
    let path = root.path().join("findings.json");
    super::super::export_workspace_findings(&workspace, &path, Some(WorkspaceExportFormat::Json))
        .unwrap();
    let document: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    for record in document["findings"].as_array().unwrap() {
        assert_eq!(record["reviewDecision"], "needs_review");
        assert_eq!(record["relationships"][0]["state"], "removed");
        assert_eq!(record["relationships"][0]["revision"], 2);
        assert_eq!(record["relationships"][0]["from"]["runId"], "owned-fixture");
    }
    assert_eq!(store.list_all_findings().unwrap(), findings);
}
