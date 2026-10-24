use super::*;
use serde_json::json;

fn receipt() -> Value {
    json!({"schemaVersion":1,"selectedFileCount":2,"sourcePartial":true,"completeRepositoryCoverage":false,
        "discoveryFileCount":1,"sharedFileCount":1,"inheritedContextRef":{"revisionId":"exact-parent"},
        "sourceEvidence":{"byteBudget":1024,"fileLimit":2,"readBytes":24,
            "files":[{"path":" app /one.rs","scopeRole":"shared-context","omittedLines":1,"lines":[{"ref":" app /one.rs:1"}]}],"omissions":{"file limit":1}}})
}

#[test]
fn partial_evidence_summary_keeps_literal_names_and_inheritance_separate() {
    let document = json!({"provenance":{"fileContext":{"receipt":receipt()}}});
    let text = receipt_lines(&document).join("\n");
    for expected in [
        "Requested files: 2 · supplied excerpts: 1",
        "Selected source partial: true · complete repository coverage: false",
        "\" app /one.rs\"",
        "exact-parent",
        "file limit",
        "1024 bytes · 2 files · 24 bytes supplied",
        "Tab reads",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
}

#[test]
fn both_origins_are_visible_without_reader_controls_in_report_projection() {
    let provenance = json!({"scopeContext":{"status":"recorded","receipt":receipt()},"fileContext":{"receipt":receipt()}});
    let text = provenance_lines(&provenance).join("\n");
    assert!(
        text.contains("FILE-GROUP CONTEXT RECEIPT") && text.contains("EVIDENCE CONTEXT RECEIPT")
    );
    assert!(text.contains("1 discovery · 1 shared-context files"));
    assert!(!text.contains("Tab reads"));
}

#[test]
fn missing_counts_and_flags_are_unrecorded_and_true_claim_is_unverified() {
    let mut receipt = receipt();
    for key in [
        "selectedFileCount",
        "sourcePartial",
        "completeRepositoryCoverage",
    ] {
        receipt.as_object_mut().unwrap().remove(key);
    }
    let text = recorded_lines(&receipt).join("\n");
    assert!(text.contains("Eligible source files: unrecorded"));
    assert!(text.contains(
        "Selected source partial: unrecorded · complete repository coverage: unrecorded"
    ));
    receipt["sourcePartial"] = json!(true);
    receipt["completeRepositoryCoverage"] = json!(true);
    assert!(recorded_lines(&receipt)
        .join("\n")
        .contains("claim is unverified"));
}

#[test]
fn invalid_receipts_never_invent_zero_supplied_files() {
    for wrapper in [
        json!({"receipt":false}),
        json!({"receipt":{"schemaVersion":2}}),
        json!({"receipt":{"schemaVersion":1,"sourceEvidence":{"files":false}}}),
        json!({"status":"unavailable","receipt":receipt()}),
    ] {
        let text = wrapper_lines(&wrapper, "RECEIPT").join("\n");
        assert!(text.contains("unavailable"));
        assert!(!text.contains("supplied excerpts: 0"));
    }
    assert!(provenance_lines(&json!({})).is_empty());
}

#[test]
fn malformed_file_rows_are_unavailable_before_any_excerpt_count() {
    for file in [
        json!(false),
        json!({"path":""}),
        json!({"path":"valid.rs","lines":false}),
        json!({"path":"valid.rs","lines":[{"ref":false}]}),
    ] {
        let mut receipt = receipt();
        receipt["sourceEvidence"]["files"] = json!([file]);
        let text = wrapper_lines(&json!({"receipt":receipt}), "RECEIPT").join("\n");
        assert!(text.contains("unavailable") && !text.contains("supplied excerpts"));
    }
}

#[test]
fn group_source_eligibility_does_not_invent_a_requested_file_count() {
    let mut receipt = receipt();
    receipt.as_object_mut().unwrap().remove("selectedFileCount");
    receipt["sourceEvidence"]["eligibleFiles"] = json!(3);
    let text = recorded_lines(&receipt).join("\n");
    assert!(text.contains("Eligible source files: 3 · supplied excerpts: 1"));
    assert!(!text.contains("Requested files"));
}
