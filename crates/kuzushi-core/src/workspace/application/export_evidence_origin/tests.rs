use super::*;

#[test]
fn explicit_model_claims_keep_source_and_capture_fields_non_observational() {
    for request_blob in [None, Some("owned-request".to_string())] {
        let evidence = FindingEvidence {
            kind: FindingEvidence::UNSCORED_MODEL_CLAIM.into(),
            file_path: "owned.rs".into(),
            line: 1,
            request_blob,
            ..Default::default()
        };
        let counts = evidence_origin_counts(&[evidence]);
        assert_eq!(counts.observed_count, 0);
        assert_eq!(counts.model_generated_reasoning_count, 1);
        assert_eq!(counts.reasoning_assertion_count, 0);
    }
}

#[test]
fn generic_reasoning_does_not_invent_model_authorship_in_exports() {
    let evidence = FindingEvidence {
        kind: "reasoning".into(),
        file_path: "owned.rs".into(),
        rationale: "Imported from external findings ledger".into(),
        ..Default::default()
    };
    assert_eq!(
        finding_evidence_origin_label(&evidence),
        "reasoning assertion"
    );
    let counts = evidence_origin_counts(&[evidence]);
    assert_eq!(counts.observed_count, 0);
    assert_eq!(counts.model_generated_reasoning_count, 0);
    assert_eq!(counts.reasoning_assertion_count, 1);
}

#[test]
fn legacy_reasoning_remains_excluded_from_observed_counts() {
    let evidence = FindingEvidence {
        kind: " ReAsOnInG ".into(),
        file_path: "owned.rs".into(),
        request_blob: Some("owned-request".into()),
        ..Default::default()
    };
    assert!(evidence.is_model_generated_reasoning());
    assert_eq!(evidence_origin_counts(&[evidence]).observed_count, 0);
}
