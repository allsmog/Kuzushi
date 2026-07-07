use super::*;

#[test]
fn enriches_object_without_replacing_existing_data() {
    let output = normalize_output_value(json!({"data": {"count": 2}}));

    assert_eq!(output["ok"], true);
    assert_eq!(output["status"], "completed");
    assert_eq!(output["summary"], "tool completed");
    assert_eq!(output["artifacts"].as_array().unwrap().len(), 0);
    assert_eq!(output["warnings"].as_array().unwrap().len(), 0);
    assert_eq!(output["errors"].as_array().unwrap().len(), 0);
    assert_eq!(output["data"]["count"], 2);
}

#[test]
fn derives_failed_contract_from_ok_false() {
    let output = normalize_output_value(json!({
        "ok": false,
        "error": "scanner missing"
    }));

    assert_eq!(output["status"], "failed");
    assert_eq!(output["errors"][0], "scanner missing");
}

#[test]
fn derives_ok_from_top_level_failed_status() {
    let output = normalize_output_value(json!({
        "status": "failed",
        "summary": "scanner failed"
    }));

    assert_eq!(output["ok"], false);
    assert_eq!(output["status"], "failed");
}

#[test]
fn failed_status_overrides_stale_ok_true() {
    let output = normalize_output_value(json!({
        "ok": true,
        "status": "failed",
        "summary": "scanner failed"
    }));

    assert_eq!(output["ok"], false);
    assert_eq!(output["status"], "failed");
}

#[test]
fn preserves_top_level_completed_status() {
    let output = normalize_output_value(json!({"status": "completed"}));

    assert_eq!(output["status"], "completed");
}

#[test]
fn preserves_top_level_failed_status() {
    let output = normalize_output_value(json!({"status": "failed"}));

    assert_eq!(output["ok"], false);
    assert_eq!(output["status"], "failed");
}

#[test]
fn normalizes_warning_and_error_messages_to_arrays() {
    let output = normalize_output_value(json!({
        "warning": "scanner degraded",
        "errors": "scanner missing"
    }));

    assert_eq!(output["warnings"][0], "scanner degraded");
    assert_eq!(output["errors"][0], "scanner missing");
}

#[test]
fn infers_summary_from_first_output_line() {
    let output = normalize_output_value(json!({
        "output": "\nsemgrep: 1 finding under /repo\nTop findings:\n- rule"
    }));

    assert_eq!(output["summary"], "semgrep: 1 finding under /repo");
}

#[test]
fn preserves_structured_domain_summary_under_data() {
    let output = normalize_output_value(json!({
        "summary": {"count": 2},
        "data": {"target": "/repo"}
    }));

    assert_eq!(output["summary"], "tool completed");
    assert_eq!(output["data"]["summary"], json!({"count": 2}));
    assert_eq!(output["data"]["target"], "/repo");
}

#[test]
fn uses_nested_string_summary_for_contract_summary() {
    let output = normalize_output_value(json!({
        "data": {"summary": "threat intel applied"}
    }));

    assert_eq!(output["summary"], "threat intel applied");
}

#[test]
fn lifts_nested_artifact_map_to_contract_artifacts() {
    let output = normalize_output_value(json!({
        "data": {
            "artifacts": {
                "report": "/tmp/report.md",
                "details": {"path": "/tmp/details.json", "kind": "json"}
            }
        }
    }));

    let artifacts = output["artifacts"].as_array().unwrap();
    assert!(artifacts
        .iter()
        .any(|artifact| artifact["path"] == "/tmp/details.json"));
    assert!(artifacts
        .iter()
        .any(|artifact| artifact["path"] == "/tmp/report.md"));
}

#[test]
fn drops_artifact_objects_without_canonical_path() {
    let output = normalize_output_value(json!({
        "artifacts": [{"label": "report", "report_path": "/tmp/report.md"}]
    }));

    assert!(output["artifacts"].as_array().unwrap().is_empty());
}

#[test]
fn preserves_unknown_domain_status_under_data() {
    let output = normalize_output_value(json!({"status": "planned"}));

    assert_eq!(output["status"], "completed");
    assert_eq!(output["data"]["status"], "planned");
}

#[test]
fn wraps_non_object_outputs() {
    let output = normalize_output_value(json!("done"));

    assert_eq!(output["ok"], true);
    assert_eq!(output["status"], "completed");
    assert_eq!(output["data"], "done");
}

#[test]
fn leaves_catalog_metadata_arrays_unwrapped() {
    let output = normalize_tool_output_contract("catalog:tools", json!([{"name": "x:y"}]));

    assert_eq!(output, json!([{"name": "x:y"}]));
}
