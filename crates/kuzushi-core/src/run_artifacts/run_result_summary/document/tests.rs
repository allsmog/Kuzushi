use super::*;
use crate::run_lifecycle::{sha256_content_digest, ArtifactReference, RunItemId};
use serde_json::json;

fn reference(body: &str) -> (RunItemId, ArtifactReference) {
    let producer = RunItemId::new();
    let reference = ArtifactReference {
        path: SafeText::operator_visible("result.json"),
        digest: SafeText::operator_visible(sha256_content_digest(body.as_bytes())),
        byte_count: body.len() as u64,
        line_count: Some(body.lines().count() as u64),
        producing_item_id: producer,
        kind: SafeText::operator_visible("json"),
        label: SafeText::operator_visible("Owned result"),
    };
    (producer, reference)
}

fn decode(body: &str) -> Result<RunResultDocument> {
    let (id, artifact) = reference(body);
    decode_correlated_result_document(id, &artifact, RunItemStatus::Completed, body)
}

#[test]
fn invalid_supplied_input_preserves_the_authenticated_primary_result() {
    let body =
        json!({"status":"completed","summary":"Owned result","output":"Retained observation",
        "data":{"inputDocument":{"schemaVersion":99,"text":"owned source"}}})
        .to_string();
    let document = decode(&body).unwrap();
    assert_eq!(document.output[0].as_str(), "Retained observation");
    assert!(document
        .supplied_input
        .unwrap()
        .unwrap_err()
        .as_str()
        .contains("version"));
    let (producer, reference) = reference(&body);
    let changed = body.replace("owned source", "changed source");
    assert!(decode_correlated_result_document(
        producer,
        &reference,
        RunItemStatus::Completed,
        &changed
    )
    .is_err());
}

#[test]
fn saved_document_retains_output_beyond_preview_limits_and_whitespace() {
    let output = (0..40)
        .map(|index| format!("  owned café {index}"))
        .collect::<Vec<_>>()
        .join("\n");
    let body = json!({"status":"completed","summary":"Owned metadata","output":output,"warnings":["Partial context"],"errors":[]}).to_string();
    let result = decode(&body).unwrap();
    assert_eq!(result.output.len(), 40);
    assert_eq!(result.output.last().unwrap().as_str(), "  owned café 39");
    assert_eq!(result.warnings[0].as_str(), "Partial context");
}

#[test]
fn altered_bytes_wrong_producer_lines_and_status_never_become_saved_output() {
    let body = json!({"status":"completed","output":"Owned text"}).to_string();
    let (id, artifact) = reference(&body);
    let changed = body.replace("Owned", "Other");
    assert!(
        decode_correlated_result_document(id, &artifact, RunItemStatus::Completed, &changed)
            .is_err()
    );
    assert!(decode_correlated_result_document(
        RunItemId::new(),
        &artifact,
        RunItemStatus::Completed,
        &body
    )
    .is_err());
    assert!(
        decode_correlated_result_document(id, &artifact, RunItemStatus::Partial, &body).is_err()
    );
    let mut invalid_lines = artifact;
    invalid_lines.line_count = Some(4);
    assert!(
        decode_correlated_result_document(id, &invalid_lines, RunItemStatus::Completed, &body)
            .is_err()
    );
}

#[test]
fn oversized_and_malformed_documents_fail_explicitly_without_truncation() {
    for value in [
        json!({"status":"completed","output":"x".repeat(MAX_OUTPUT_BYTES+1)}),
        json!({"status":"completed","output":"\n".repeat(MAX_OUTPUT_LINES+1)}),
        json!({"status":"completed","warnings":[{"unknown":"message"}]}),
        json!({"status":"completed","output":{"unknown":"shape"}}),
        json!({"status":"completed","errors":vec!["Owned";MAX_MESSAGES+1]}),
    ] {
        assert!(decode(&value.to_string()).is_err());
    }
    let (id, artifact) = reference("{bad JSON");
    assert!(decode_correlated_result_document(
        id,
        &artifact,
        RunItemStatus::Completed,
        "{bad JSON"
    )
    .is_err());
    assert!(decode(&"x".repeat(MAX_DOCUMENT_BYTES + 1)).is_err());
}
