use super::*;
use serde_json::json;
mod dispatch;

fn failure(root: &Path, tool: &str, status: &str, error: &str) {
    let mut run = crate::run_artifacts::RunSummary::running(
        "failed-child",
        "tool",
        Some(tool.into()),
        root.display().to_string(),
    );
    run.status = status.into();
    run.error = Some(error.into());
    crate::run_artifacts::write_run_summary(root, &run).unwrap();
}

fn snapshot(root: &Path, entry: Value) -> CampaignJobSnapshot {
    job_snapshot(
        root,
        &Value::Null,
        &json!({"jobId":"context-001", "tool":"threat-model:build"}),
        &Map::from_iter([("context-001".into(), entry)]),
    )
}

#[test]
fn failed_job_exposes_its_correlated_run_error_without_rewriting_metadata() {
    let root = tempfile::tempdir().unwrap();
    failure(
        root.path(),
        "threat-model:build",
        "failed",
        "Provider authentication failed.",
    );
    let metadata =
        crate::workspace::workspace_state_dir(root.path()).join("runs/failed-child/run.json");
    let before = std::fs::read(&metadata).unwrap();
    let row = snapshot(
        root.path(),
        json!({"state":"failed", "runId":"failed-child"}),
    );
    assert_eq!(
        row.reason.as_deref(),
        Some("Provider authentication failed.")
    );
    assert_eq!(std::fs::read(metadata).unwrap(), before);
}

#[test]
fn explicit_dispatcher_reason_takes_precedence_over_the_run_error() {
    let root = tempfile::tempdir().unwrap();
    failure(
        root.path(),
        "threat-model:build",
        "failed",
        "Provider authentication failed.",
    );
    let row = snapshot(
        root.path(),
        json!({"state":"parked", "runId":"failed-child", "reason":"source changed"}),
    );
    assert_eq!(row.reason.as_deref(), Some("source changed"));
}

#[test]
fn foreign_run_metadata_cannot_supply_a_failure_reason_or_findings() {
    let root = tempfile::tempdir().unwrap();
    failure(
        root.path(),
        "threat-model:build",
        "failed",
        "Unrelated recorded failure",
    );
    let path =
        crate::workspace::workspace_state_dir(root.path()).join("runs/failed-child/run.json");
    let mut value: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    value["runId"] = json!("different-child");
    value["findings"] = json!(42);
    std::fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
    let row = snapshot(
        root.path(),
        json!({"state":"failed","runId":"failed-child"}),
    );
    assert_eq!(row.reason, None);
    assert_eq!(row.findings, None);
}

#[test]
fn incomplete_run_metadata_cannot_invent_a_canonical_failure_reason() {
    let root = tempfile::tempdir().unwrap();
    let directory = crate::workspace::workspace_state_dir(root.path()).join("runs/failed-child");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(
        directory.join("run.json"),
        json!({"tool":"threat-model:build","status":"failed","error":"Unverified minimal JSON"})
            .to_string(),
    )
    .unwrap();
    assert_eq!(
        snapshot(
            root.path(),
            json!({"state":"failed","runId":"failed-child"})
        )
        .reason,
        None
    );
}

#[test]
fn legacy_count_metadata_cannot_supply_another_runs_count() {
    let root = tempfile::tempdir().unwrap();
    let directory = crate::workspace::workspace_state_dir(root.path()).join("runs/failed-child");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(
        directory.join("run.json"),
        json!({"runId":"foreign","status":"completed","findings":42}).to_string(),
    )
    .unwrap();
    let row = snapshot(
        root.path(),
        json!({"state":"failed","runId":"failed-child"}),
    );
    assert_eq!(row.findings, None);
    assert_eq!(row.reason, None);
}

#[test]
fn invalid_costs_and_unknown_fields_cannot_supply_canonical_failure_details() {
    let root = tempfile::tempdir().unwrap();
    for (field, value) in [("costUsd", json!(-1.0)), ("unknownField", json!(true))] {
        failure(
            root.path(),
            "threat-model:build",
            "failed",
            "Invalid canonical metadata",
        );
        let path =
            crate::workspace::workspace_state_dir(root.path()).join("runs/failed-child/run.json");
        let mut body: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        body[field] = value;
        std::fs::write(path, serde_json::to_vec(&body).unwrap()).unwrap();
        assert_eq!(
            snapshot(
                root.path(),
                json!({"state":"failed","runId":"failed-child"})
            )
            .reason,
            None
        );
    }
}

#[test]
fn unrelated_live_missing_and_unsafe_run_references_cannot_supply_a_failure_reason() {
    let root = tempfile::tempdir().unwrap();
    let entry = json!({"state":"failed", "runId":"failed-child"});
    failure(root.path(), "other:tool", "failed", "Unrelated failure");
    assert!(snapshot(root.path(), entry.clone()).reason.is_none());
    failure(
        root.path(),
        "threat-model:build",
        "running",
        "Not a terminal error",
    );
    assert!(snapshot(root.path(), entry.clone()).reason.is_none());
    failure(
        root.path(),
        "threat-model:build",
        "failed",
        "Recorded failure",
    );
    assert!(snapshot(
        root.path(),
        json!({"state":"running", "runId":"failed-child"})
    )
    .reason
    .is_none());
    assert!(
        snapshot(root.path(), json!({"state":"failed", "runId":"missing"}))
            .reason
            .is_none()
    );
    assert!(snapshot(
        root.path(),
        json!({"state":"failed", "runId":"../../outside"})
    )
    .reason
    .is_none());
}

#[test]
fn failure_reason_uses_the_shared_bounded_safe_diagnostic_projection() {
    let root = tempfile::tempdir().unwrap();
    failure(
        root.path(),
        "threat-model:build",
        "failed",
        &format!("\u{1b}[2J\n{}", "x".repeat(800)),
    );
    let row = snapshot(
        root.path(),
        json!({"state":"failed", "runId":"failed-child"}),
    );
    let reason = row.reason.unwrap();
    assert!(reason.chars().count() <= 500);
    assert!(!reason.chars().any(char::is_control));
    assert!(reason.ends_with('…'));
}

#[test]
fn escaped_run_reference_cannot_supply_a_finding_count() {
    let root = tempfile::tempdir().unwrap();
    let outside = crate::workspace::workspace_state_dir(root.path()).join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("run.json"), r#"{"findings":999}"#).unwrap();
    let row = snapshot(root.path(), json!({"state":"failed", "runId":"../outside"}));
    assert_eq!(row.findings, None);
    assert_eq!(row.reason, None);
}

#[test]
fn explicit_queue_diagnostics_are_bounded_without_rewriting_the_queue() {
    let root = tempfile::tempdir().unwrap();
    let entry = json!({"state":"parked","reason":format!("\u{1b}[2J\n{}", "x".repeat(1000))});
    let before = entry.clone();
    let row = snapshot(root.path(), entry.clone());
    let reason = row.reason.unwrap();
    assert!(reason.chars().count() <= 500);
    assert!(!reason.chars().any(char::is_control));
    assert_eq!(entry, before);
}

#[test]
fn lifetime_attempts_survive_a_reset_retry_counter_without_guessing_legacy_history() {
    let root = tempfile::tempdir().unwrap();
    let row = snapshot(
        root.path(),
        json!({"state":"completed","attempts":1,"dispatches":2,
        "attemptRuns":[{"runId":"canceled"},{"runId":"completed"}]}),
    );
    assert_eq!(row.attempts, 1);
    assert_eq!(row.dispatches, Some(2));
    assert_eq!(
        snapshot(root.path(), json!({"attempts":1})).dispatches,
        None
    );
    assert_eq!(snapshot(root.path(), Value::Null).dispatches, Some(0));
    for entry in [
        json!({"attempts":2,"dispatches":1}),
        json!({"attempts":1,"dispatches":1,"attemptRuns":[{"runId":"one"},{"runId":"two"}]}),
        json!({"attempts":1,"dispatches":"2"}),
    ] {
        assert_eq!(snapshot(root.path(), entry).dispatches, None);
    }
}
