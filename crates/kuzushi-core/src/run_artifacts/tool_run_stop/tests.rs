use super::*;
use crate::run_artifacts::{
    load_run_summary, try_record_tool_run_complete,
    try_record_tool_run_started_with_reproducibility,
};
use crate::scan::{PreparedProcessGroup, ScanCancellation};
use serde_json::json;

fn child() -> (RegisteredChild, u32) {
    let mut command = std::process::Command::new("sleep");
    command.arg("30");
    let group = PreparedProcessGroup::configure(&mut command).unwrap();
    let process = command.spawn().unwrap();
    let pid = process.id();
    (
        ScanCancellation::default()
            .register_prepared_child(process, group)
            .unwrap(),
        pid,
    )
}

fn started(record: ToolRunRecord<'_>) {
    try_record_tool_run_started_with_reproducibility(
        record,
        &json!({}),
        Some("fixture:model".into()),
        None,
        vec![],
    )
    .unwrap();
}

#[test]
fn stopped_child_records_operator_intent_and_keeps_unknown_cost_unknown() {
    for (disposition, expected) in [
        (CancellationDisposition::Canceled, "canceled"),
        (CancellationDisposition::Interrupted, "interrupted"),
    ] {
        let root = tempfile::tempdir().unwrap();
        let record = ToolRunRecord::new(root.path(), "stopped", "tool", "fixture:scan");
        started(record);
        let (child, pid) = child();
        let summary = stop_tool_run_child(record, &child, disposition)
            .unwrap()
            .unwrap();
        assert_eq!(summary.status, expected);
        assert_eq!(summary.model.as_deref(), Some("fixture:model"));
        assert_eq!(summary.cost_usd, None);
        assert!(summary.checked_cost_report().unwrap().is_unavailable());
        assert_stopped(pid);
        assert_eq!(
            load_run_summary(root.path(), "stopped").unwrap().status,
            expected
        );
        assert!(summary
            .artifacts
            .iter()
            .any(|artifact| artifact.path.ends_with("input.json")));
    }
}

#[test]
fn completed_child_result_wins_the_stop_race_without_rewriting_artifacts() {
    let root = tempfile::tempdir().unwrap();
    let record = ToolRunRecord::new(root.path(), "done", "tool", "fixture:scan");
    started(record);
    try_record_tool_run_complete(
        record,
        &json!({"ok":true,"status":"completed","findings":[]}),
    )
    .unwrap();
    let path = super::super::run_artifact_path(root.path(), "done", "run.json");
    let before = std::fs::read(&path).unwrap();
    let (child, pid) = child();
    let summary = stop_tool_run_child(record, &child, CancellationDisposition::Canceled)
        .unwrap()
        .unwrap();
    assert_stopped(pid);
    assert_eq!(summary.status, "completed");
    assert_eq!(std::fs::read(path).unwrap(), before);
}

#[test]
fn child_stopped_before_start_does_not_manufacture_execution_metadata() {
    let root = tempfile::tempdir().unwrap();
    let record = ToolRunRecord::new(root.path(), "not-started", "tool", "fixture:scan");
    let (child, pid) = child();
    assert!(
        stop_tool_run_child(record, &child, CancellationDisposition::Canceled)
            .unwrap()
            .is_none()
    );
    assert_stopped(pid);
    assert!(!root
        .path()
        .join(".kuzushi/v3/runs/not-started/run.json")
        .exists());
}

fn assert_stopped(pid: u32) {
    let probe = std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .output()
        .unwrap();
    assert!(
        !probe.status.success(),
        "Owned child must be reaped before returning"
    );
}

#[test]
fn stopping_closes_open_model_tool_and_semantic_activity_before_the_terminal() {
    use crate::run_lifecycle::*;
    for (disposition, expected) in [
        (CancellationDisposition::Canceled, RunItemStatus::Canceled),
        (
            CancellationDisposition::Interrupted,
            RunItemStatus::Interrupted,
        ),
    ] {
        let root = tempfile::tempdir().unwrap();
        let record = ToolRunRecord::new(root.path(), "active", "tool", "fixture:scan");
        started(record);
        seed_open_activity(root.path());
        let (child, pid) = child();
        let summary = stop_tool_run_child(record, &child, disposition)
            .unwrap()
            .unwrap();
        assert_stopped(pid);
        let projection = load_run_projection_unhydrated(root.path(), "active").unwrap();
        assert_eq!(projection.health, ProjectionHealth::Healthy);
        assert_eq!(projection.terminal.unwrap().status, expected);
        assert_eq!(projection.calls.len(), 2);
        assert!(projection
            .calls
            .values()
            .all(|call| call.status == expected));
        assert!(projection
            .tasks
            .values()
            .all(|task| task.status == expected));
        assert_eq!(projection.plan.unwrap().status, expected);
        assert_eq!(summary.cost_usd, None);
        assert!(summary.checked_cost_report().unwrap().is_unavailable());
    }
}

fn seed_open_activity(target: &std::path::Path) {
    use crate::run_lifecycle::*;
    let writer = RunItemWriter::open(target, "active", None).unwrap();
    let task = RunTaskId::new();
    let make = |item| RunItemRecord::new(RunItemId::new(), RunItemSource::Workflow, item);
    writer
        .emit_and_flush(make(RunItemV1::PlanUpdated {
            revision: 1,
            title: SafeText::operator_visible("Fixture study"),
            status: RunItemStatus::Pending,
            task_ids: vec![task],
        }))
        .unwrap();
    writer
        .emit_and_flush(
            make(RunItemV1::TaskUpdated {
                title: SafeText::operator_visible("Fixture task"),
                status: RunItemStatus::Pending,
                detail: None,
            })
            .with_task(task),
        )
        .unwrap();
    seed_open_calls(&writer, task);
    writer.shutdown().unwrap();
}

fn seed_open_calls(
    writer: &crate::run_lifecycle::RunItemWriter,
    task: crate::run_lifecycle::RunTaskId,
) {
    use crate::run_lifecycle::*;
    let tool = RunItemId::new();
    let tool_call = RunCallId::new();
    let make = |item| {
        RunItemRecord::new(tool, RunItemSource::Dispatch, item)
            .with_call(tool_call)
            .with_task(task)
    };
    writer
        .emit_and_flush(make(RunItemV1::ToolCallRequested {
            tool_name: SafeText::operator_visible("fixture:scan"),
            operation_fingerprint: OperationFingerprint::from_bytes(b"fixture tool"),
            safe_option_names: vec![],
        }))
        .unwrap();
    writer
        .emit_and_flush(make(RunItemV1::ToolCallStarted {
            tool_name: SafeText::operator_visible("fixture:scan"),
            runtime: None,
            model: None,
        }))
        .unwrap();
    writer
        .emit_and_flush(
            RunItemRecord::new(
                RunItemId::new(),
                RunItemSource::Runtime,
                RunItemV1::ModelCallStarted {
                    provider: SafeText::operator_visible("fixture"),
                    model: SafeText::operator_visible("fixture:model"),
                    operation_fingerprint: OperationFingerprint::from_bytes(b"fixture model"),
                },
            )
            .with_call(RunCallId::new())
            .with_task(task)
            .with_parent(tool),
        )
        .unwrap();
}

#[test]
fn published_terminal_intent_wins_a_late_stop_before_summary_publication() {
    let root = tempfile::tempdir().unwrap();
    let record = ToolRunRecord::new(root.path(), "done", "tool", "fixture:scan");
    started(record);
    let running = load_run_summary_without_repair(root.path(), "done").unwrap();
    try_record_tool_run_complete(
        record,
        &json!({"ok":true,"status":"completed","findings":[]}),
    )
    .unwrap();
    // Model the crash boundary after typed terminal publication, before run.json.
    let completed = load_run_summary_without_repair(root.path(), "done").unwrap();
    super::super::terminal_intent::write_terminal_intent(root.path(), &completed).unwrap();
    crate::run_artifacts::write_run_summary(root.path(), &running).unwrap();
    let (child, pid) = child();
    let summary = stop_tool_run_child(record, &child, CancellationDisposition::Canceled)
        .unwrap()
        .unwrap();
    assert_stopped(pid);
    assert_eq!(summary.status, "completed");
    let projection =
        crate::run_lifecycle::load_run_projection_unhydrated(root.path(), "done").unwrap();
    assert_eq!(
        projection.health,
        crate::run_lifecycle::ProjectionHealth::Healthy
    );
    assert_eq!(
        projection.terminal.unwrap().status,
        crate::run_lifecycle::RunItemStatus::Completed
    );
}
