use super::*;
use kuzushi_core::run_artifacts::{record_tool_run_started, ToolRunRecord};
use serde_json::json;

const RUN_ID: &str = "trace-live-receipt";

fn trace_output(target: &Path) -> serde_json::Value {
    let tree = kuzushi_core::incremental_index::current_workspace_tree_hash(target).unwrap();
    json!({"ok":true,"data":{
        "tool":"trace:expand","version":1,"findingFingerprint":"finding",
        "steps":[],"openQuestions":["caller unresolved"],
        "evidenceDeltas":["no intermediary hop"],"treeHash":tree
    }})
}

fn observed_trace(target: &Path, result: &serde_json::Value) -> ToolRunRecordEffect {
    let workspace = WorkspaceTarget::new(target).unwrap();
    let target = workspace.root();
    record_tool_run_started(
        ToolRunRecord::new(target, RUN_ID, "tool", "trace:expand"),
        &json!({"fingerprint":"finding"}),
    );
    let observation =
        kuzushi_core::run_lifecycle::RunObservationHandle::jsonl(target, RUN_ID).unwrap();
    let call = kuzushi_core::modules::ApplicationToolCall::start(
        observation,
        "trace:expand",
        &json!({}),
        None,
        None,
    )
    .unwrap();
    let completion = call.completion_from_result(&Ok(result.clone()));
    ToolRunRecordEffect {
        target: Some(target.to_path_buf()),
        run_id: Some(RUN_ID.to_string()),
        tool_name: "trace:expand".to_string(),
        outcome: ToolRunRecordOutcome::ObservedComplete {
            result: result.clone(),
            completion,
        },
    }
}

fn app_with_live_trace(target: &Path, result: &serde_json::Value) -> ShellApp {
    let workspace = WorkspaceTarget::new(target).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.cache_tool_snapshot("trace:expand", result);
    app
}

fn trace_receipt(app: &ShellApp) -> &str {
    app.domain()
        .trace_expansion_for_finding("finding")
        .unwrap()
        .last_outcome
        .as_deref()
        .unwrap()
}

#[test]
fn successful_persistence_refreshes_the_live_trace_receipt() {
    let target = tempfile::tempdir().unwrap();
    let result = trace_output(target.path());
    let record = observed_trace(target.path(), &result);
    let mut app = app_with_live_trace(target.path(), &result);
    assert_eq!(app.target(), record.target.as_deref());
    assert!(!trace_receipt(&app).contains(RUN_ID));
    app.record_tool_run_effect(record);
    assert!(trace_receipt(&app).contains(RUN_ID));
    assert!(trace_receipt(&app).contains("source unchanged"));
    let snapshot = app.domain().trace_expansion_for_finding("finding").unwrap();
    assert_eq!(snapshot.open_questions, ["caller unresolved"]);
    assert_eq!(snapshot.evidence_deltas, ["no intermediary hop"]);
}

#[test]
fn failed_persistence_does_not_replace_the_live_trace_with_history() {
    let target = tempfile::tempdir().unwrap();
    let result = trace_output(target.path());
    let record = observed_trace(target.path(), &result);
    let blocked = target
        .path()
        .join(".kuzushi/v3/runs")
        .join(RUN_ID)
        .join("result.json");
    std::fs::create_dir(&blocked).unwrap();
    std::fs::write(blocked.join("blocker"), "retain").unwrap();
    let mut app = app_with_live_trace(target.path(), &result);
    let before = trace_receipt(&app).to_string();
    app.record_tool_run_effect(record);
    assert_eq!(trace_receipt(&app), before);
    assert!(blocked.is_dir());
}

#[test]
fn completed_trace_does_not_refresh_a_different_current_target() {
    let old_target = tempfile::tempdir().unwrap();
    let current_target = tempfile::tempdir().unwrap();
    let result = trace_output(old_target.path());
    let record = observed_trace(old_target.path(), &result);
    let mut current = result.clone();
    current["data"]["openQuestions"] = json!(["current target question"]);
    let mut app = app_with_live_trace(current_target.path(), &current);
    let before = trace_receipt(&app).to_string();
    app.record_tool_run_effect(record);
    assert_eq!(trace_receipt(&app), before);
    assert_eq!(
        app.domain()
            .trace_expansion_for_finding("finding")
            .unwrap()
            .open_questions,
        ["current target question"]
    );
}
