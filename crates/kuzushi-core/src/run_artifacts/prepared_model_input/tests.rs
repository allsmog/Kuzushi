use super::*;

fn supplied() -> Value {
    json!({"inputDocument":{"schemaVersion":1,"text":"Frozen owned source\nDelivery is not established."},
        "frozenInput":{"sources":[{"path":"owned.c","text":"// inert"}]}})
}

#[test]
fn missing_prepared_input_leaves_legacy_results_unchanged() {
    let root = tempfile::tempdir().unwrap();
    let output = json!({"status":"failed","data":{"error":"owned failure"}});
    assert_eq!(attach(root.path(), "missing", output.clone()), output);
}

#[test]
fn retained_input_survives_all_stopped_results_without_claiming_delivery() {
    let root = tempfile::tempdir().unwrap();
    retain_prepared_model_input(root.path(), "prepared", "owned:inspect", &supplied()).unwrap();
    for status in ["failed", "canceled", "interrupted", "blocked"] {
        let output = attach(root.path(), "prepared", json!({"status":status}));
        assert_eq!(output["status"], status);
        assert_eq!(output["data"]["inputDocument"], supplied()["inputDocument"]);
        assert!(output["data"]["findings"].is_null());
    }
}

#[test]
fn a_second_request_cannot_replace_the_first_prepared_input() {
    let root = tempfile::tempdir().unwrap();
    retain_prepared_model_input(root.path(), "prepared", "owned:inspect", &supplied()).unwrap();
    let changed = json!({"inputDocument":{"schemaVersion":1,"text":"replacement"}});
    let error = retain_prepared_model_input(root.path(), "prepared", "owned:inspect", &changed)
        .unwrap_err()
        .to_string();
    assert!(error.contains("use a new run"));
    assert_eq!(
        load(root.path(), "prepared").unwrap(),
        Some(supplied()["inputDocument"].clone())
    );
}

#[test]
fn retention_refuses_excessive_input_before_writing_a_request_artifact() {
    let root = tempfile::tempdir().unwrap();
    let data = json!({"inputDocument":{"schemaVersion":1,"text":"x".repeat(MAX_BYTES)}});
    assert!(retain_prepared_model_input(root.path(), "large", "owned:inspect", &data).is_err());
    assert!(load(root.path(), "large").unwrap().is_none());
}

#[test]
fn corrupted_prepared_input_keeps_the_failure_and_discloses_its_read_error() {
    let root = tempfile::tempdir().unwrap();
    retain_prepared_model_input(root.path(), "prepared", "owned:inspect", &supplied()).unwrap();
    fs::write(run_artifact_path(root.path(), "prepared", LEAF), "{}\n").unwrap();
    let output = attach(
        root.path(),
        "prepared",
        json!({"status":"failed","errors":["transport"]}),
    );
    assert_eq!(output["errors"], json!(["transport"]));
    assert!(output["data"]["inputDocument"]["error"]
        .as_str()
        .unwrap()
        .contains("changed since retention"));
}

#[test]
fn complete_result_input_remains_authoritative_when_prepared_artifact_is_unavailable() {
    let root = tempfile::tempdir().unwrap();
    let output = json!({"status":"completed","data":supplied()});
    assert_eq!(attach(root.path(), "missing", output.clone()), output);
}

#[test]
fn deleted_retained_input_is_disclosed_and_cannot_be_replaced_at_the_same_run() {
    let root = tempfile::tempdir().unwrap();
    retain_prepared_model_input(root.path(), "deleted", "owned:inspect", &supplied()).unwrap();
    fs::remove_file(run_artifact_path(root.path(), "deleted", LEAF)).unwrap();
    let output = attach(root.path(), "deleted", json!({"status":"interrupted"}));
    assert!(output["data"]["inputDocument"]["error"]
        .as_str()
        .unwrap()
        .contains("missing after retention"));
    assert!(
        retain_prepared_model_input(root.path(), "deleted", "owned:inspect", &supplied()).is_err()
    );
}

#[test]
fn stopped_run_receipts_publish_the_retained_input() {
    for status in ["failed", "canceled", "interrupted"] {
        let root = tempfile::tempdir().unwrap();
        let record = ToolRunRecord::new(root.path(), status, "run", "owned:inspect");
        try_record_tool_run_started_with_reproducibility(
            record,
            &json!({}),
            None,
            None,
            Vec::new(),
        )
        .unwrap();
        retain_prepared_model_input(root.path(), status, "owned:inspect", &supplied()).unwrap();
        match status {
            "failed" => try_record_tool_run_failed(record, "owned transport failure").unwrap(),
            "canceled" => try_record_tool_run_canceled(record, "owned cancellation").unwrap(),
            _ => try_record_tool_run_interrupted(record, "owned interruption").unwrap(),
        }
        assert_result(root.path(), status);
    }
}

#[test]
fn dead_process_recovery_retains_prepared_input_without_rereading_source() {
    let root = tempfile::tempdir().unwrap();
    let run = "owned-dead-process";
    let summary = RunSummary::running(run, "run", Some("owned:inspect".into()), "target")
        .with_process_id(u32::MAX);
    write_run_summary(root.path(), &summary).unwrap();
    retain_prepared_model_input(root.path(), run, "owned:inspect", &supplied()).unwrap();
    assert_eq!(
        load_run_summary(root.path(), run).unwrap().status,
        "interrupted"
    );
    assert_result(root.path(), run);
    let path = run_artifact_path(root.path(), run, "result.json");
    let original = fs::read(&path).unwrap();
    assert_eq!(
        load_run_summary(root.path(), run).unwrap().status,
        "interrupted"
    );
    assert_eq!(fs::read(path).unwrap(), original);
}

#[test]
fn concurrent_preparation_retains_exactly_one_request_record() {
    let root = tempfile::tempdir().unwrap();
    let count = std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            retain_prepared_model_input(root.path(), "same-run", "owned:inspect", &supplied())
        });
        let second = scope.spawn(|| {
            retain_prepared_model_input(root.path(), "same-run", "owned:inspect", &supplied())
        });
        [first.join().unwrap(), second.join().unwrap()]
            .into_iter()
            .filter(Result::is_ok)
            .count()
    });
    assert_eq!(count, 1);
    assert_eq!(
        load(root.path(), "same-run").unwrap(),
        Some(supplied()["inputDocument"].clone())
    );
}

fn assert_result(root: &Path, run: &str) {
    let (_, text) = read_run_artifact_text(root, run, "result.json")
        .require("result")
        .unwrap();
    let output: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(output["data"]["inputDocument"], supplied()["inputDocument"]);
}
