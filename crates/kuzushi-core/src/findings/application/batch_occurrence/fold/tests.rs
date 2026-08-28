use super::*;

#[test]
fn stronger_proof_beats_higher_severity_for_representative_selection() {
    let mut stronger = finding("stronger evidence", Severity::High);
    stronger.static_proof_state = Some(StaticProofState::StaticallyConfirmed);
    let higher_severity = finding("critical signal", Severity::Critical);
    let mut accumulator = OccurrenceAccumulator::default();

    accumulator.observe_trial(&["run-1".to_string()], vec![higher_severity, stronger]);
    let row = accumulator.finish(
        "identity:shared".to_string(),
        LogicalTrialCounts {
            planned: 1,
            completed: 1,
            failed: 0,
            pending: 0,
        },
    );

    assert_eq!(row.representative_title, "stronger evidence");
    assert_eq!(row.representative_severity, "high");
}

fn finding(title: &str, severity: Severity) -> Finding {
    Finding::new_tool(
        "semgrep",
        "rule/cwe-78",
        "src/shell.rs",
        10,
        Some(10),
        severity,
        title,
    )
}
