use super::super::export_projection_model::WorkspaceRunExportContext;
use super::*;
use crate::findings::Severity;
use crate::run_artifacts::{RunSummary, RunTargetGitMetadata};

fn fixture() -> (tempfile::TempDir, WorkspaceTarget, FindingStore, Finding) {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    std::fs::write(root.path().join("owned.txt"), "Owned greeting\n").unwrap();
    store
        .record_run_started("first", workspace.root(), "completed")
        .unwrap();
    let mut finding = Finding::new_tool(
        "owned-source",
        "greeting",
        "owned.txt",
        1,
        None,
        Severity::Info,
        "Labeled observation",
    );
    finding.dedup_key = Some("owned:greeting".into());
    store.insert_finding("first", &finding).unwrap();
    let finding = store.list_all_findings().unwrap().remove(0);
    (root, workspace, store, finding)
}

#[test]
fn recorded_run_git_never_fills_an_unknown_observation_snapshot_git() {
    let (_root, workspace, store, finding) = fixture();
    let summary = RunSummary {
        target_git: Some(RunTargetGitMetadata {
            sha: "labeled-run-checkout".into(),
            branch: Some("owned".into()),
            dirty: true,
        }),
        ..Default::default()
    };
    let context = WorkspaceRunExportContext::from_summary(&summary);
    let contexts = std::collections::HashMap::from([("first".into(), context)]);
    let mut records =
        super::super::export_projection::workspace_finding_export_records_with_context(
            std::slice::from_ref(&finding),
            &[],
            &contexts,
        );
    attach_observation_sources(&store, std::slice::from_ref(&finding), &mut records).unwrap();
    let source = records[0]
        .provenance
        .observation_source
        .as_ref()
        .unwrap()
        .clone();
    assert_eq!(source.run_id, "first");
    assert_eq!(source.git_commit, None);
    assert_eq!(
        records[0].provenance.run_git.as_ref().unwrap().sha,
        "labeled-run-checkout"
    );
    let cells = csv_source_fields(&records[0]);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&cells[1]).unwrap()["generationId"],
        finding.id.unwrap()
    );
    std::fs::remove_file(workspace.root().join("owned.txt")).unwrap();
    attach_observation_sources(&store, &[finding], &mut records).unwrap();
    assert_eq!(
        records[0].provenance.observation_source.as_ref().unwrap(),
        &source
    );
}

#[test]
fn source_export_requires_matching_rows_and_does_not_invent_a_missing_generation() {
    let (_root, _workspace, store, finding) = fixture();
    assert!(attach_observation_sources(&store, &[finding], &mut []).is_err());
    let mut missing = Finding::new_tool(
        "owned",
        "missing",
        "missing.txt",
        1,
        None,
        Severity::Info,
        "Labeled missing generation",
    );
    missing.id = Some(i64::MAX);
    let mut records =
        super::super::export_projection::workspace_finding_export_records_with_reviews(
            std::slice::from_ref(&missing),
            &[],
        );
    attach_observation_sources(&store, &[missing], &mut records).unwrap();
    assert!(records[0].provenance.observation_source.is_none());
    assert_eq!(csv_source_fields(&records[0]), ["null", "null", "[]"]);
}

#[test]
fn relationship_references_keep_historical_sources_after_every_finding_is_reobserved() {
    let (_root, workspace, store, first) = fixture();
    let mut other = Finding::new_tool(
        "owned-source",
        "second",
        "owned.txt",
        1,
        None,
        Severity::Info,
        "Labeled second observation",
    );
    other.dedup_key = Some("owned:second".into());
    let other_id = store.insert_finding("first", &other).unwrap();
    let relation = store
        .propose_finding_relationship(
            first.id.unwrap(),
            other_id,
            crate::findings::FindingRelationshipKind::Duplicate,
            "Labeled historical pair",
            None,
        )
        .unwrap();
    store
        .record_run_started("later", workspace.root(), "completed")
        .unwrap();
    store.insert_finding("later", &first).unwrap();
    store.insert_finding("later", &other).unwrap();
    let findings = store.list_all_findings().unwrap();
    assert_eq!(
        findings.len(),
        2,
        "Both strong identities must be observed again"
    );
    let mut records =
        super::super::export_projection::workspace_finding_export_records_with_reviews(
            &findings,
            &[],
        );
    super::super::export_relationships::attach_relationships(&store, &findings, &mut records)
        .unwrap();
    attach_observation_sources(&store, &findings, &mut records).unwrap();
    let all = records
        .iter()
        .flat_map(|record| record.provenance.relationship_sources.iter())
        .collect::<Vec<_>>();
    assert!(
        all.iter()
            .any(|source| source.generation_id == relation.from.finding_id
                && source.run_id == "first")
    );
    assert!(all
        .iter()
        .any(|source| source.generation_id == relation.to.finding_id && source.run_id == "first"));
    assert!(
        records.iter().all(|record| record
            .provenance
            .observation_source
            .as_ref()
            .unwrap()
            .run_id
            == "later"),
        "{:?}",
        records
            .iter()
            .map(|record| (&record.tool, &record.provenance.observation_source))
            .collect::<Vec<_>>()
    );
}

#[test]
fn markdown_keeps_current_location_outside_historical_relationship_sources() {
    let (_root, workspace, store, first) = fixture();
    let second = Finding::new_tool(
        "owned-source",
        "second",
        "owned.txt",
        1,
        None,
        Severity::Info,
        "Labeled second observation",
    );
    let second_id = store.insert_finding("first", &second).unwrap();
    store
        .propose_finding_relationship(
            first.id.unwrap(),
            second_id,
            crate::findings::FindingRelationshipKind::Uncertain,
            "Labeled historical source references",
            None,
        )
        .unwrap();
    let output = workspace.root().join("bundle");
    super::super::export_workspace_findings(
        &workspace,
        &output,
        Some(WorkspaceExportFormat::MarkdownBundle),
    )
    .unwrap();
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(output.join("manifest.json")).unwrap()).unwrap();
    for record in manifest["findings"].as_array().unwrap() {
        let text = std::fs::read_to_string(output.join(record["path"].as_str().unwrap())).unwrap();
        let location = text.find("**Location:**").unwrap();
        let relationships = text.find("## Recorded relationships").unwrap();
        let sources = text.find("### Relationship source references").unwrap();
        assert!(location < relationships && relationships < sources);
        assert!(text.contains("**Observation Git:** `not recorded`"));
    }
}
