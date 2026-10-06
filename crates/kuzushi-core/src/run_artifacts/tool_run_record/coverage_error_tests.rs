use super::*;

#[test]
fn partial_scan_omissions_remain_readable_beside_the_primary_reason() {
    let output = json!({"status":"partial", "summary":"Source changed during the scan", "data":{"scanErrors":["src/omitted.rs: parser stopped"]}});
    assert_eq!(
        tool_run_output_error(&output),
        "Source changed during the scan\nIncomplete coverage: src/omitted.rs: parser stopped"
    );
}

#[test]
fn explicit_failure_reason_is_preserved_when_partial_scan_also_reports_omissions() {
    let output = json!({"status":"partial", "summary":"scan", "errors":["Source could not be authenticated"],"data":{"scanErrors":["rule skipped"]}});
    assert_eq!(
        tool_run_output_error(&output),
        "Source could not be authenticated\nIncomplete coverage: rule skipped"
    );
}

#[test]
fn partial_omission_preview_is_bounded_while_the_result_retains_all_errors() {
    let long = "x".repeat(300);
    let output =
        json!({"status":"partial","data":{"scanErrors":[long,"two\nfull detail","three","four"]}});
    let preview = partial_scan_omission_preview(&output).unwrap();
    assert!(preview.starts_with(&format!("{}…", "x".repeat(240))));
    assert!(preview.contains("two…; three; 1 more reported omissions"));
    assert_eq!(output["data"]["scanErrors"][0].as_str().unwrap().len(), 300);
    assert_eq!(output["data"]["scanErrors"][1], "two\nfull detail");
}

#[test]
fn scan_omissions_do_not_override_another_terminal_outcome() {
    for status in ["completed", "failed", "skipped"] {
        let output =
            json!({"status":status,"summary":"original reason","data":{"scanErrors":["gap"]}});
        assert_eq!(partial_scan_omission_preview(&output), None);
        assert_eq!(tool_run_output_error(&output), "original reason");
    }
    assert_eq!(
        partial_scan_omission_preview(&json!({"status":"partial","data":{"scanErrors":[]}})),
        None
    );
    assert_eq!(
        partial_scan_omission_preview(&json!({"status":"partial","data":{"scanErrors":"invalid"}})),
        None
    );
}
