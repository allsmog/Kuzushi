use super::*;
use crate::run_artifacts::{run_dir, write_run_summary, RunSummary};

#[test]
fn canceled_execution_survives_without_an_engine_outcome_and_is_exported() {
    let root = tempfile::tempdir().unwrap();
    let run = "owned-canceled-attempt";
    let summary = RunSummary::running(
        run,
        "run",
        Some("sast:scan".into()),
        root.path().display().to_string(),
    )
    .canceled("Owned operator cancellation");
    let path = write_run_summary(root.path(), &summary).unwrap();
    let before = std::fs::read(&path).unwrap();
    let attempt = attempt_receipt(root.path(), run).unwrap();
    assert_eq!(attempt.run_status.as_deref(), Some("canceled"));
    assert!(attempt.scan.is_none());
    let mut report = planned_report(root.path());
    report.attempts = vec![attempt];
    let value = serde_json::to_value(InvestigationReportDocument::Study(report)).unwrap();
    assert_eq!(value["attempts"][0]["runStatus"], "canceled");
    assert!(value["attempts"][0]["scan"].is_null());
    assert_eq!(std::fs::read(path).unwrap(), before);
}

#[test]
fn missing_and_malformed_run_status_stay_unavailable_without_repair() {
    let root = tempfile::tempdir().unwrap();
    let dir = run_dir(root.path(), "metadata-unavailable");
    std::fs::create_dir_all(&dir).unwrap();
    let missing = attempt_receipt(root.path(), "metadata-unavailable").unwrap();
    assert!(missing.run_status.is_none());
    assert!(serde_json::to_value(missing)
        .unwrap()
        .get("runStatus")
        .is_none());
    let path = dir.join("run.json");
    std::fs::write(&path, "{malformed owned metadata").unwrap();
    let before = std::fs::read(&path).unwrap();
    let malformed = attempt_receipt(root.path(), "metadata-unavailable").unwrap();
    assert!(malformed.run_status.is_none());
    assert_eq!(std::fs::read(path).unwrap(), before);
}
