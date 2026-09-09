use super::*;
use crate::run_artifacts::{
    record_tool_run_started, try_record_tool_run_complete_settled, ToolRunRecord,
};

fn save(target: &Path, run_id: &str, questions: Value) {
    let record = ToolRunRecord::new(target, run_id, "tool", "trace:expand");
    record_tool_run_started(record, &json!({"fingerprint":"finding"}));
    let output = json!({"ok":true,"data":{
        "tool":"trace:expand","version":1,"findingFingerprint":"finding",
        "steps":[],"openQuestions":questions,"evidenceDeltas":["no intermediary hop"]
    }});
    let observation =
        crate::run_lifecycle::RunObservationHandle::jsonl(record.target, record.run_id).unwrap();
    let call = crate::modules::ApplicationToolCall::start(
        observation.clone(),
        "trace:expand",
        &json!({}),
        None,
        None,
    )
    .unwrap();
    let completion = call.completion_from_result(&Ok(output.clone()));
    try_record_tool_run_complete_settled(record, &output, &observation, completion).unwrap();
}

#[test]
fn recovery_keeps_complete_zero_step_outcome_and_finding_identity() {
    let target = tempfile::tempdir().unwrap();
    save(
        target.path(),
        "tool-1000-first",
        json!(["caller unresolved"]),
    );
    let saved = load_latest_trace_expansion(target.path(), "finding")
        .unwrap()
        .unwrap();
    assert_eq!(saved.run_id, "tool-1000-first");
    assert!(saved.result.steps.is_empty());
    assert_eq!(saved.result.open_questions, ["caller unresolved"]);
    assert_eq!(saved.result.evidence_deltas, ["no intermediary hop"]);
    assert_eq!(saved.source, TraceExpansionSource::Unrecorded);
    assert!(load_latest_trace_expansion(target.path(), "other")
        .unwrap()
        .is_none());
}

#[test]
fn newest_complete_outcome_can_clear_previous_questions() {
    let target = tempfile::tempdir().unwrap();
    save(
        target.path(),
        "tool-1000-first",
        json!(["caller unresolved"]),
    );
    save(target.path(), "tool-1001-second", json!([]));
    let saved = load_latest_trace_expansion(target.path(), "finding")
        .unwrap()
        .unwrap();
    assert_eq!(saved.run_id, "tool-1001-second");
    assert!(saved.result.open_questions.is_empty());
}

#[test]
fn modified_result_cannot_replace_the_recorded_outcome() {
    let target = tempfile::tempdir().unwrap();
    save(
        target.path(),
        "tool-1000-first",
        json!(["caller unresolved"]),
    );
    let path =
        crate::run_artifacts::run_artifact_path(target.path(), "tool-1000-first", "result.json");
    let mut value: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    value["data"]["openQuestions"] = json!(["unrecorded replacement"]);
    std::fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(load_latest_trace_expansion(target.path(), "finding").is_err());
}

#[test]
fn recorded_source_distinguishes_current_changed_and_missing_identity() {
    let target = tempfile::tempdir().unwrap();
    std::fs::write(target.path().join("input.c"), "int n = 1;\n").unwrap();
    let hash = crate::incremental_index::current_workspace_tree_hash(target.path()).unwrap();
    let value = json!({"data":{"treeHash": hash}});
    assert_eq!(
        recorded_source(target.path(), &value),
        TraceExpansionSource::Current
    );
    std::fs::write(target.path().join("input.c"), "int n = 2;\n").unwrap();
    assert_eq!(
        recorded_source(target.path(), &value),
        TraceExpansionSource::Changed
    );
    assert_eq!(
        recorded_source(target.path(), &json!({})),
        TraceExpansionSource::Unrecorded
    );
}
