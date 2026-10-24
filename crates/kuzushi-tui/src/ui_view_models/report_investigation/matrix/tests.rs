use super::*;
use kuzushi_core::findings::{
    BatchOccurrenceReport, BatchOccurrenceRow, ContextCaseOccurrenceReport,
    ContextMatrixOccurrenceReport, IdentityFoldPolicy,
};

fn observation(path: &str, seen: usize) -> BatchOccurrenceRow {
    BatchOccurrenceRow {
        fold_key: path.into(),
        identity_id: Some(format!("owned-{seen}")),
        identity_basis: None,
        seen,
        completed: 3,
        planned: 3,
        failed: 0,
        severities: vec!["info".into()],
        locations: vec![path.into()],
        titles: vec!["Same owned observation".into()],
        fingerprints: vec![format!("owned-fingerprint-{seen}")],
        run_ids: vec![format!("owned-run-{seen}")],
        representative_fingerprint: format!("owned-fingerprint-{seen}"),
        representative_title: "Same owned observation".into(),
        representative_severity: "info".into(),
        representative_location: path.into(),
    }
}

fn report() -> ContextMatrixOccurrenceReport {
    ContextMatrixOccurrenceReport {
        schema_version: 1,
        campaign_id: "owned-recap".into(),
        plan_sha256: "a".repeat(64),
        baseline_case_id: "baseline".into(),
        cases: vec![ContextCaseOccurrenceReport {
            id: "baseline".into(),
            label: "Owned baseline".into(),
            threat_model_ref: serde_json::Value::Null,
            occurrence: BatchOccurrenceReport {
                schema_version: 1,
                batch_id: "owned-recap".into(),
                equivalence_key: "owned-conditions".into(),
                identity_fold: IdentityFoldPolicy::default(),
                planned: 3,
                completed: 3,
                failed: 0,
                pending: 0,
                gate: None,
                trials: Vec::new(),
                rows: vec![
                    observation("main.rs:1", 3),
                    observation(" literal 東京.rs:1", 2),
                ],
            },
        }],
    }
}

#[test]
fn report_recap_disambiguates_same_title_observations_without_changing_recurrence() {
    let receipt = report();
    let before = receipt.clone();
    let text = case_lines(&receipt).join("\n");
    for expected in [
        "observed 3 / 3",
        "observed 2 / 3",
        "Location: \"main.rs:1\"",
        "Location: \" literal 東京.rs:1\"",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    assert_eq!(receipt, before);
}

#[test]
fn report_recap_details_keep_complete_recorded_observation_references() {
    let receipt = report();
    let text = observation_receipts(&receipt).join("\n");
    for seen in [2, 3] {
        for expected in [
            format!("Fingerprint: owned-fingerprint-{seen}"),
            format!("Identity: owned-{seen}"),
            format!("Run: owned-run-{seen}"),
        ] {
            assert!(text.contains(&expected), "{expected}: {text}");
        }
    }
    assert!(text.contains("Observation receipts: Owned baseline"));
}
