use super::*;
use crate::capabilities::campaign::{
    BatchGateStatus, ScanBatchGateBinding, ScanBatchGateCounts, ScanBatchGatePolicy,
};
use crate::findings::{BatchOccurrenceReport, IdentityFoldPolicy, Severity};

fn gate(threshold: Option<Severity>, qualifying: usize, completed: usize) -> ScanBatchGateOutcome {
    ScanBatchGateOutcome::new(
        "owned-study",
        "sha256:recorded-conditions",
        &ScanBatchGatePolicy {
            fail_on: threshold,
            sarif: None,
        },
        ScanBatchGateCounts {
            planned_trials: 3,
            completed_trials: completed,
            failed_trials: 0,
            pending_trials: 3 - completed,
            completed_run_ids: vec!["run-1".into()],
            blocking_safe_fold_count: qualifying,
            sarif_written: false,
        },
        ScanBatchGateBinding {
            logical_terminal_state_sha256: "state".into(),
            blocking_findings_sha256: "findings".into(),
            sarif_path: None,
            sarif_sha256: None,
        },
    )
}

#[test]
fn missing_receipt_does_not_invent_a_policy() {
    assert_eq!(
        batch_severity_summary(None),
        "Severity assessment: unavailable"
    );
}

#[test]
fn unconfigured_cutoff_does_not_describe_security_as_disabled() {
    let receipt = gate(None, 0, 3);
    assert_eq!(
        batch_severity_summary(Some(&receipt)),
        "Severity cutoff: not configured"
    );
    assert_eq!(receipt.status, BatchGateStatus::Disabled);
}

#[test]
fn recorded_severity_count_is_distinct_from_proof_or_security_status() {
    for (count, result, noun, status) in [
        (0, "not reached", "findings", BatchGateStatus::Passed),
        (1, "reached", "finding", BatchGateStatus::Failed),
        (2, "reached", "findings", BatchGateStatus::Failed),
    ] {
        let receipt = gate(Some(Severity::High), count, 3);
        assert_eq!(
            batch_severity_summary(Some(&receipt)),
            format!(
                "Severity cutoff high: {result} · {count} qualifying {noun} in completed passes"
            )
        );
        assert_eq!(receipt.status, status);
    }
}

#[test]
fn incomplete_work_only_describes_observations_from_completed_passes() {
    let receipt = gate(Some(Severity::Critical), 0, 1);
    let output = batch_severity_summary(Some(&receipt));
    assert!(output.contains("critical: not reached"), "{output}");
    assert!(output.ends_with("in completed passes"), "{output}");
    assert_eq!(receipt.status, BatchGateStatus::Incomplete);
}

fn empty_report(gate: Option<ScanBatchGateOutcome>) -> BatchOccurrenceReport {
    BatchOccurrenceReport {
        schema_version: 1,
        batch_id: "owned-study".into(),
        equivalence_key: "sha256:recorded-conditions".into(),
        identity_fold: IdentityFoldPolicy::Safe,
        planned: 3,
        completed: 1,
        failed: 0,
        pending: 2,
        gate,
        trials: vec![],
        rows: vec![],
    }
}

#[test]
fn human_output_preserves_counts_and_receipts_without_mutating_json_statuses() {
    let report = empty_report(Some(gate(Some(Severity::High), 0, 1)));
    let before = serde_json::to_value(&report).unwrap();
    let output = report.output();
    assert!(
        output.contains("completed 1 / planned 3 · failed 0 · pending 2"),
        "{output}"
    );
    assert!(
        output.contains("Severity cutoff high: not reached"),
        "{output}"
    );
    assert!(output.contains("does not establish proof"), "{output}");
    assert!(
        output.contains("Equivalence: sha256:recorded-conditions"),
        "{output}"
    );
    assert!(output.contains("completed runs 1"), "{output}");
    assert_eq!(before["gate"]["status"], "incomplete");
    assert_eq!(before["gate"]["securityStatus"], "passed");
    assert_eq!(serde_json::to_value(&report).unwrap(), before);
}

#[test]
fn empty_legacy_output_retains_equivalence_without_inventing_an_assessment() {
    let output = empty_report(None).output();
    assert!(
        output.contains("Severity assessment: unavailable"),
        "{output}"
    );
    assert!(
        output.find("no findings observed").unwrap() < output.find("Equivalence:").unwrap(),
        "{output}"
    );
}
