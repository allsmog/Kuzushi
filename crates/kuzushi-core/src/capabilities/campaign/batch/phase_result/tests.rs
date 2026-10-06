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
