use super::*;
use crate::{FindingStore, V2Config, WorkspaceTarget};

#[test]
fn standalone_codeql_reported_gaps_reach_the_partial_ledger() {
    let (_root, workspace, store) = fixture();
    let output = dispatch(&workspace, &store, json!({}), || {
        Ok(ScanEngineOutput {
            findings: vec![],
            codeql_sarif_documents: vec![],
            scan_errors: vec!["go: labeled missing database".into()],
        })
    });
    assert_eq!(output["status"], "partial");
    assert_eq!(
        output["data"]["scanErrors"][0],
        "go: labeled missing database"
    );
    assert_eq!(
        store.run_status("codeql-settled").unwrap().as_deref(),
        Some("partial")
    );
}

fn fixture() -> (tempfile::TempDir, WorkspaceTarget, FindingStore) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("owned.js"), "// Owned inert source.\n").unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    (root, workspace, store)
}

fn dispatch(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    input: Value,
    analyze: impl FnOnce() -> Result<ScanEngineOutput>,
) -> Value {
    let config = V2Config::default();
    let trace = crate::run_artifacts::TraceHandle::jsonl(workspace.root(), "codeql-settled");
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(workspace),
        findings_store: Some(store),
        trace: Some(&trace),
        cancellation: None,
        authorization: Default::default(),
    };
    run_with_analysis(workspace.root(), &input, &ctx, analyze).unwrap()
}

#[test]
fn source_changed_after_query_keeps_partial_work_without_static_evidence_indexing() {
    let (root, workspace, store) = fixture();
    let output = dispatch(&workspace, &store, json!({"whiteboxStatic":true}), || {
        std::fs::write(
            root.path().join("README.md"),
            "Planned inert operator edit.\n",
        )?;
        Ok(ScanEngineOutput {
            findings: vec![Finding::new_tool(
                "codeql",
                "owned/marker",
                "owned.js",
                1,
                None,
                crate::findings::Severity::Low,
                "Owned parser observation",
            )],
            ..Default::default()
        })
    });
    assert_eq!(output["status"], "partial");
    assert_eq!(output["data"]["sourceCheckCurrent"], false);
    assert!(output["data"]["staticEvidenceOmitted"]
        .as_str()
        .unwrap()
        .contains("source verification"));
    assert!(output.pointer("/data/persisted/staticEvidence").is_none());
    assert!(output["output"]
        .as_str()
        .unwrap()
        .contains("static evidence was not indexed"));
    assert_eq!(
        store
            .list_findings_for_scan_id("codeql-settled")
            .unwrap()
            .len(),
        1
    );
    let (_, raw) = crate::run_artifacts::read_run_artifact_text(
        workspace.root(),
        "codeql-settled",
        "findings.json",
    )
    .require("observations")
    .unwrap();
    assert_eq!(serde_json::from_str::<Vec<Finding>>(&raw).unwrap().len(), 1);
}

#[test]
fn query_failure_with_source_drift_does_not_publish_observations() {
    let (root, workspace, store) = fixture();
    let output = dispatch(&workspace, &store, json!({}), || {
        std::fs::write(
            root.path().join("README.md"),
            "Planned inert operator edit.\n",
        )?;
        anyhow::bail!("Owned query adapter failed")
    });
    assert_eq!(output["status"], "failed");
    assert_eq!(output["data"]["sourceCheckCurrent"], false);
    assert!(output.to_string().contains("Owned query adapter failed"));
    assert!(store.list_all_findings().unwrap().is_empty());
}

#[test]
fn untraced_query_publishes_the_same_committed_run_identity() {
    let (_root, workspace, store) = fixture();
    let config = V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: Some(&store),
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let output = run_with_analysis(workspace.root(), &json!({}), &ctx, || {
        Ok(ScanEngineOutput {
            findings: vec![Finding::new_tool(
                "codeql",
                "owned/marker",
                "owned.js",
                1,
                None,
                crate::findings::Severity::Low,
                "Owned parser observation",
            )],
            ..Default::default()
        })
    })
    .unwrap();
    let run = output["data"]["persisted"]["runId"].as_str().unwrap();
    let (_, raw) =
        crate::run_artifacts::read_run_artifact_text(workspace.root(), run, "findings.json")
            .require("committed observations")
            .unwrap();
    let findings: Vec<Finding> = serde_json::from_str(&raw).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].scan_id.as_deref(), Some(run));
}
