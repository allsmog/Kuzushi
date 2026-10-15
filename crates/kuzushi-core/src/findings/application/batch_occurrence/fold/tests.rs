use super::*;

#[test]
fn correlated_legacy_child_results_preserve_observations_and_current_recurrence() {
    let target = tempfile::tempdir().unwrap();
    let root = target.path();
    let store = FindingStore::open(root.join("findings.db")).unwrap();
    for (parent, child) in [
        ("parent-prior", "child-prior"),
        ("parent-current", "child-current"),
    ] {
        let record = crate::run_artifacts::ToolRunRecord::new(root, parent, "run", "sast:scan");
        crate::run_artifacts::try_record_tool_run_started_with_reproducibility(
            record,
            &serde_json::json!({}),
            None,
            None,
            vec![],
        )
        .unwrap();
        crate::run_artifacts::try_record_tool_run_complete(
            record,
            &serde_json::json!({"status":"completed", "data":{"runIds":[child]}}),
        )
        .unwrap();
        store.record_run_started(child, root, "completed").unwrap();
        store
            .insert_finding(
                child,
                &Finding::new_tool("owned", child, "source.rs", 1, None, Severity::High, child),
            )
            .unwrap();
    }
    let trials = vec![BatchTrialReport {
        trial: 1,
        job_id: "job".into(),
        state: "completed".into(),
        attempts: 1,
        run_id: Some("parent-current".into()),
        attempt_run_ids: vec!["parent-prior".into(), "parent-current".into()],
        finding_run_ids: vec![],
        failure_reason: None,
    }];
    let rows = occurrence_rows(
        root,
        &store,
        &trials,
        IdentityFoldPolicy::Safe,
        LogicalTrialCounts::from_trials(&trials),
    )
    .unwrap();
    assert_eq!(rows.len(), 2);
    for row in rows {
        assert_eq!(row.run_ids, [row.representative_title.clone()]);
        assert_eq!(
            row.seen,
            usize::from(row.representative_title == "child-current")
        );
    }
}

#[test]
fn stronger_proof_beats_higher_severity_for_representative_selection() {
    let mut stronger = finding("stronger evidence", Severity::High);
    stronger.static_proof_state = Some(StaticProofState::StaticallyConfirmed);
    let higher_severity = finding("critical signal", Severity::Critical);
    let mut accumulator = OccurrenceAccumulator::default();

    accumulator.observe_finding("run-1", &higher_severity);
    accumulator.observe_finding("run-1", &stronger);
    accumulator.seen = 1;
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
