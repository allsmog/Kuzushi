use super::*;
use crate::run_artifacts::{record_tool_run_complete, record_tool_run_started, ToolRunRecord};
use crate::workflow_attempts::{load_phase_attempt_ledger, phase_attempt_ledger_path};

fn completed_run(root: &Path, id: &str) {
    let record = ToolRunRecord::new(root, id, "tool", "sast:scan");
    record_tool_run_started(record, &json!({}));
    record_tool_run_complete(
        record,
        &json!({"ok":true,"data":{"fixture":"phase handoff only"}}),
    );
}

#[test]
fn incomplete_trials_never_create_a_complete_scan_verdict() {
    assert_eq!(batch_outcome(0, 0), PhaseAttemptOutcome::Failed);
    assert_eq!(batch_outcome(0, 3), PhaseAttemptOutcome::Failed);
    assert_eq!(batch_outcome(1, 3), PhaseAttemptOutcome::Partial);
    assert_eq!(batch_outcome(3, 4), PhaseAttemptOutcome::Partial);
    assert_eq!(batch_outcome(3, 3), PhaseAttemptOutcome::Completed);
}

#[test]
fn all_partial_attempts_remain_reviewable_without_becoming_complete() {
    let target = tempfile::tempdir().unwrap();
    let record = ToolRunRecord::new(target.path(), "partial-only", "tool", "sast:scan");
    record_tool_run_started(record, &json!({}));
    record_tool_run_complete(
        record,
        &json!({"ok":true,"status":"partial","data":{"findingsCount":0}}),
    );
    let runs = vec!["partial-only".into()];
    let outcome = persisted_batch_outcome(target.path(), &runs, 0, 3).unwrap();
    assert_eq!(outcome, PhaseAttemptOutcome::Partial);
    let id = persist_result(target.path(), &runs, outcome, None).unwrap();
    let ledger = load_phase_attempt_ledger(target.path()).unwrap();
    assert_eq!(
        ledger.attempt(&id).unwrap().completed.outcome,
        PhaseAttemptOutcome::Partial
    );
    assert!(ledger.attempt(&id).unwrap().disposition.is_none());
}

#[test]
fn failed_or_unreadable_attempts_cannot_forge_partial_acceptance() {
    let target = tempfile::tempdir().unwrap();
    let record = ToolRunRecord::new(target.path(), "failed-only", "tool", "sast:scan");
    record_tool_run_started(record, &json!({}));
    record_tool_run_complete(record, &json!({"ok":false,"status":"failed"}));
    assert_eq!(
        persisted_batch_outcome(target.path(), &["failed-only".into()], 0, 3).unwrap(),
        PhaseAttemptOutcome::Failed
    );
    assert!(persisted_batch_outcome(target.path(), &["unavailable".into()], 0, 3).is_err());
}

#[test]
fn persisted_scan_remains_unselected_and_reentry_does_not_duplicate_it() {
    let target = tempfile::tempdir().unwrap();
    completed_run(target.path(), "trial-one");
    completed_run(target.path(), "trial-two");
    let runs = vec!["trial-one".into(), "trial-two".into()];
    let attempt =
        persist_result(target.path(), &runs, PhaseAttemptOutcome::Completed, None).unwrap();
    let path = phase_attempt_ledger_path(target.path());
    let before = std::fs::read(&path).unwrap();
    assert_eq!(
        persist_result(target.path(), &runs, PhaseAttemptOutcome::Completed, None).unwrap(),
        attempt
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let ledger = load_phase_attempt_ledger(target.path()).unwrap();
    let result = ledger.attempt(&attempt).unwrap();
    assert_eq!(result.completed.run_refs, runs);
    assert_eq!(result.completed.phase, WorkflowPhase::Scan);
    assert!(result.disposition.is_none());
}

#[test]
fn interrupted_compatibility_append_reuses_the_typed_attempt() {
    let target = tempfile::tempdir().unwrap();
    completed_run(target.path(), "partial-trial");
    let runs = vec!["partial-trial".into()];
    let attempt = persist_result(target.path(), &runs, PhaseAttemptOutcome::Partial, None).unwrap();
    std::fs::write(phase_attempt_ledger_path(target.path()), "").unwrap();
    assert_eq!(
        persist_result(target.path(), &runs, PhaseAttemptOutcome::Partial, None).unwrap(),
        attempt
    );
    assert_eq!(
        load_phase_attempt_ledger_v2(target.path())
            .unwrap()
            .attempts
            .len(),
        1
    );
    assert_eq!(
        load_phase_attempt_ledger(target.path())
            .unwrap()
            .attempts()
            .count(),
        1
    );
}

#[test]
fn source_content_drift_blocks_selection_without_erasing_observations() {
    let target = tempfile::tempdir().unwrap();
    let source = target.path().join("main.rs");
    std::fs::write(&source, "fn main() {}\n").unwrap();
    let registry = ModuleRegistry::with_v2_builtins();
    compile_scan_batch_plan(ScanBatchPlanSpec {
        root: target.path(),
        batch_id: Some("batch-source".into()),
        trials: 3,
        requested_workers: 1,
        gate_policy: ScanBatchGatePolicy::default(),
        prepared_input: json!({"taskMode":"manual","tasks":["secret-scan"]}),
        config: &V2Config::default(),
        registry: &registry,
    })
    .unwrap();
    assert!(source_selection_block(target.path(), "batch-source")
        .unwrap()
        .is_none());
    completed_run(target.path(), "original-source");
    std::fs::write(&source, "fn main() { println!(\"changed\"); }\n").unwrap();
    let blocked = source_selection_block(target.path(), "batch-source").unwrap();
    assert!(blocked
        .as_deref()
        .unwrap()
        .contains("earlier source content"));
    let attempt = persist_result(
        target.path(),
        &["original-source".into()],
        PhaseAttemptOutcome::Partial,
        blocked,
    )
    .unwrap();
    let ledger = load_phase_attempt_ledger(target.path()).unwrap();
    assert!(ledger
        .attempt(&attempt)
        .unwrap()
        .completed
        .selection_blocked_reason
        .is_some());
    assert_eq!(
        ledger.attempt(&attempt).unwrap().completed.run_refs,
        ["original-source"]
    );
}

fn retried_report() -> crate::findings::BatchOccurrenceReport {
    use crate::findings::{BatchOccurrenceReport, BatchTrialReport, IdentityFoldPolicy};
    let trial = |index: usize, run: &str, history: Vec<&str>| BatchTrialReport {
        trial: index,
        job_id: format!("trial-{index}"),
        state: "completed".into(),
        attempts: 1,
        run_id: Some(run.into()),
        attempt_run_ids: history.into_iter().map(str::to_string).collect(),
        finding_run_ids: vec![run.into()],
        failure_reason: None,
    };
    BatchOccurrenceReport {
        schema_version: 1,
        batch_id: "retry".into(),
        equivalence_key: "fixture".into(),
        identity_fold: IdentityFoldPolicy::UNRESOLVED_RUN_SCOPE,
        planned: 2,
        completed: 2,
        failed: 0,
        pending: 0,
        gate: None,
        rows: vec![],
        trials: vec![
            trial(1, "first", vec!["first"]),
            trial(2, "second", vec!["canceled", "second"]),
        ],
    }
}

#[test]
fn complete_scan_selects_final_trials_and_preserves_canceled_attempt_history() {
    let target = tempfile::tempdir().unwrap();
    completed_run(target.path(), "first");
    completed_run(target.path(), "second");
    let stopped = ToolRunRecord::new(target.path(), "canceled", "tool", "sast:scan");
    record_tool_run_started(stopped, &json!({}));
    crate::run_artifacts::try_record_tool_run_canceled(stopped, "owned fixture stop").unwrap();
    let report = retried_report();
    let runs = report.phase_result_run_ids().unwrap();
    assert_eq!(runs, ["first", "second"]);
    assert_eq!(
        report.all_attempt_run_ids(),
        ["canceled", "first", "second"]
    );
    let id = persist_result(target.path(), &runs, PhaseAttemptOutcome::Completed, None).unwrap();
    let ledger = load_phase_attempt_ledger(target.path()).unwrap();
    assert_eq!(ledger.attempt(&id).unwrap().completed.run_refs, runs);
    assert!(persist_result(
        target.path(),
        &report.all_attempt_run_ids(),
        PhaseAttemptOutcome::Completed,
        None
    )
    .is_err());
}

#[test]
fn incomplete_scan_retains_every_attempt_and_inconsistent_completion_is_rejected() {
    let mut report = retried_report();
    report.completed = 1;
    report.pending = 1;
    report.trials[1].state = "parked".into();
    assert_eq!(
        report.phase_result_run_ids().unwrap(),
        report.all_attempt_run_ids()
    );
    report.completed = 2;
    assert!(report.phase_result_run_ids().is_err());
    report.trials[1].state = "completed".into();
    report.trials[1].run_id = None;
    assert!(report.phase_result_run_ids().is_err());
}
