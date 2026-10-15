use super::*;
use kuzushi_core::run_artifacts::{
    record_tool_run_started, try_record_tool_run_complete_settled, ToolRunRecord,
};
use serde_json::json;

mod source_history;

#[test]
fn trace_reopens_zero_step_result_with_question_notes_and_run_reference() {
    let target = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    let record = ToolRunRecord::new(target.path(), "trace-restart", "tool", "trace:expand");
    record_tool_run_started(record, &json!({"fingerprint":"finding"}));
    let output = json!({"ok":true,"data":{
        "tool":"trace:expand","version":1,"findingFingerprint":"finding",
        "steps":[],"openQuestions":["caller unresolved"],"evidenceDeltas":["no new hop"]
    }});
    let observation =
        kuzushi_core::run_lifecycle::RunObservationHandle::jsonl(record.target, record.run_id)
            .unwrap();
    let call = kuzushi_core::modules::ApplicationToolCall::start(
        observation.clone(),
        "trace:expand",
        &json!({}),
        None,
        None,
    )
    .unwrap();
    let completion = call.completion_from_result(&Ok(output.clone()));
    try_record_tool_run_complete_settled(record, &output, &observation, completion).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.hydrate_trace_expansion_from_store("finding");
    let snapshot = app.domain().trace_expansion_for_finding("finding").unwrap();
    assert!(snapshot.steps.is_empty());
    assert_eq!(snapshot.open_questions, ["caller unresolved"]);
    assert_eq!(snapshot.evidence_deltas, ["no new hop"]);
    let receipt = snapshot.last_outcome.as_deref().unwrap();
    assert!(receipt.contains("0 new steps"));
    assert!(receipt.contains("trace-restart"));
    assert!(receipt.contains("source identity not recorded"));
}

#[test]
fn completed_trace_can_clear_resolved_questions_and_notes() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let mut data = json!({"findingFingerprint":"finding","steps":[],
        "openQuestions":["previous question"],"evidenceDeltas":["previous note"]});
    assert!(cache_trace_expansion_snapshot(
        &mut app,
        "trace:expand",
        &data
    ));
    data["openQuestions"] = json!([]);
    data["evidenceDeltas"] = json!([]);
    assert!(cache_trace_expansion_snapshot(
        &mut app,
        "trace:expand",
        &data
    ));
    let snapshot = app.domain().trace_expansion_for_finding("finding").unwrap();
    assert!(snapshot.open_questions.is_empty());
    assert!(snapshot.evidence_deltas.is_empty());
    assert!(snapshot.last_outcome.is_some());
}
