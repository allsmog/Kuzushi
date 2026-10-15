use super::*;
use crate::workspace::{export_workspace_findings, WorkspaceExportFormat};

#[test]
fn export_keeps_goal_history_and_source_receipts_separate_from_verdicts() {
    let f = Fixture::new();
    let brief = f.brief(0);
    let before = f.page(&brief);
    let row = &before["rows"][0];
    f.call(
        "findings:goal-assess",
        f.assessment(&brief, row, "direct", 0),
    )
    .unwrap();
    f.call(
        "findings:goal-assess",
        f.assessment(&brief, row, "cleared", 1),
    )
    .unwrap();
    let path = f.workspace.root().join(".kuzushi/reports/goals.json");
    export_workspace_findings(&f.workspace, &path, Some(WorkspaceExportFormat::Json)).unwrap();
    let json: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let records = json["findings"].as_array().unwrap();
    let history = records
        .iter()
        .find_map(|record| record["goalAssessments"].as_array())
        .unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0]["briefRef"], brief);
    assert_eq!(history[0]["basis"], row["basis"]);
    assert!(history[0]["briefText"]
        .as_str()
        .unwrap()
        .contains("owner policy"));
    assert_eq!(history[1]["relevance"], "cleared");
    assert!(records
        .iter()
        .all(|record| record["reviewDecision"] == "needs_review"));
    let path = f.workspace.root().join(".kuzushi/reports/goals.sarif");
    export_workspace_findings(&f.workspace, &path, Some(WorkspaceExportFormat::Sarif)).unwrap();
    let sarif: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert!(sarif["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .any(|row| row["properties"]["kuzushiGoalAssessments"]
            .as_array()
            .is_some_and(|rows| rows.len() == 2)));
    assert!(
        crate::workspace::workspace_export_omitted_fields(WorkspaceExportFormat::Csv)
            .contains(&"goalAssessments")
    );
    assert!(f.store.list_all_review_decisions().unwrap().is_empty());
}

#[test]
fn goal_history_survives_projection_rebuild() {
    use crate::storage_v3::writer_actor::{ControlCommand, StorageWriterActor, WriterCommand};
    let f = Fixture::new();
    let brief = f.brief(0);
    let page = f.page(&brief);
    let row = &page["rows"][0];
    f.call(
        "findings:goal-assess",
        f.assessment(&brief, row, "outside", 0),
    )
    .unwrap();
    let id = row["basis"]["findingId"].as_i64().unwrap();
    let history = f.store.finding_goal_history(id).unwrap();
    let log = f.workspace.event_log_dir();
    let db = f.workspace.findings_db_path();
    StorageWriterActor::commit_blocking(
        log,
        db,
        WriterCommand::Control(ControlCommand::RebuildProjection),
    )
    .unwrap();
    let reopened = FindingStore::open_read_only(f.workspace.findings_db_path()).unwrap();
    assert_eq!(reopened.finding_goal_history(id).unwrap(), history);
    assert!(reopened.list_all_review_decisions().unwrap().is_empty());
}
