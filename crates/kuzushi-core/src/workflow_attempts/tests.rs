use super::*;
use crate::WorkflowPhase;
use std::collections::BTreeSet;
use std::fs;

fn completed(outcome: PhaseAttemptOutcome) -> PhaseAttemptCompleted {
    PhaseAttemptCompleted::new(
        WorkflowPhase::Scan,
        vec!["scan-1".to_string()],
        PhaseTargetSnapshot {
            target: "/target".to_string(),
            revision: Some("abc".to_string()),
            dirty: false,
        },
        outcome,
    )
}

fn receipt() -> PhaseAttemptReceipt {
    PhaseAttemptReceipt {
        run_count: 2,
        elapsed_secs: 17,
        cost: "$0.1250".to_string(),
        changed_findings: 3,
        changed_artifacts: vec!["result.json".to_string(), "trace.jsonl".to_string()],
        interaction_count: 1,
        rerun_specification: Some("run semgrep:scan".to_string()),
        actions: vec![
            PhaseResultAction::Select,
            PhaseResultAction::SelectAndContinue,
            PhaseResultAction::Open,
        ],
        recommended_next: Some("select this Scan, then open Review".to_string()),
    }
}

#[test]
fn durable_result_receipt_round_trips_typed_restart_metadata() {
    let target = tempfile::tempdir().unwrap();
    let attempt = completed(PhaseAttemptOutcome::Completed).with_receipt(receipt());
    append_phase_attempt_completed(target.path(), attempt.clone()).unwrap();

    let restored = load_phase_attempt_ledger(target.path())
        .unwrap()
        .attempt(&attempt.attempt_id)
        .unwrap()
        .completed
        .clone();

    assert_eq!(restored.receipt, attempt.receipt);
    assert_eq!(
        restored.receipt.unwrap().actions,
        vec![
            PhaseResultAction::Select,
            PhaseResultAction::SelectAndContinue,
            PhaseResultAction::Open,
        ]
    );
}

#[test]
fn legacy_completed_event_without_receipt_still_loads() {
    let event = serde_json::json!({
        "event": "phase_attempt_completed",
        "attemptId": "phase-legacy",
        "phase": "scan",
        "runRefs": ["scan-legacy"],
        "targetSnapshot": {"target": "/target", "revision": "abc", "dirty": false},
        "outcome": "completed",
        "derivation": "original",
        "completedAtUnix": 1
    });
    let parsed: PhaseAttemptEvent = serde_json::from_value(event).unwrap();
    let PhaseAttemptEvent::PhaseAttemptCompleted(completed) = parsed else {
        panic!("expected completed event");
    };
    assert_eq!(completed.receipt, None);
    assert_eq!(completed.selection_blocked_reason, None);
}

#[test]
fn recovering_loader_returns_only_the_valid_jsonl_prefix() {
    let target = tempfile::tempdir().unwrap();
    let attempt = completed(PhaseAttemptOutcome::Completed);
    let valid = serde_json::to_string(&PhaseAttemptEvent::PhaseAttemptCompleted(
        attempt.clone(),
    ))
    .unwrap();
    let path = phase_attempt_ledger_path(target.path());
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, format!("{valid}\n{{malformed\n{valid}\n")).unwrap();

    let recovered = load_phase_attempt_events_recovering(target.path()).unwrap();

    assert_eq!(recovered.events.len(), 1);
    assert_eq!(recovered.malformed_line, Some(2));
    assert!(recovered.is_degraded());
    assert!(load_phase_attempt_events(target.path()).is_err());
}

#[test]
fn recovering_ledger_projects_the_valid_prefix_and_degraded_state() {
    let target = tempfile::tempdir().unwrap();
    let attempt = completed(PhaseAttemptOutcome::Completed);
    let valid = serde_json::to_string(&PhaseAttemptEvent::PhaseAttemptCompleted(
        attempt.clone(),
    ))
    .unwrap();
    let path = phase_attempt_ledger_path(target.path());
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, format!("{valid}\nnot-json\n")).unwrap();

    let recovered = load_phase_attempt_ledger_recovering(target.path()).unwrap();

    assert!(recovered.is_degraded());
    assert_eq!(recovered.malformed_line, Some(2));
    assert!(recovered.ledger.attempt(&attempt.attempt_id).is_some());
}

#[test]
fn round_trips_completed_and_selected_attempts() {
    let target = tempfile::tempdir().unwrap();
    let attempt = completed(PhaseAttemptOutcome::Completed);
    append_phase_attempt_completed(target.path(), attempt.clone()).unwrap();
    append_phase_attempt_disposition(
        target.path(),
        PhaseAttemptDispositionRecorded::new(
            &attempt.attempt_id,
            PhaseAttemptDisposition::Selected {
                acknowledged_partial: false,
            },
        ),
    )
    .unwrap();

    let ledger = load_phase_attempt_ledger(target.path()).unwrap();
    assert_eq!(
        ledger
            .selected_for(WorkflowPhase::Scan, &attempt.target_snapshot)
            .map(|record| record.completed.run_refs.as_slice()),
        Some(["scan-1".to_string()].as_slice())
    );
    assert!(ledger
        .unresolved_for(WorkflowPhase::Scan, &attempt.target_snapshot)
        .is_none());
}

#[test]
fn same_second_unresolved_attempts_follow_append_order() {
    let mut first = completed(PhaseAttemptOutcome::Completed);
    first.attempt_id = "phase-z-first".to_string();
    first.completed_at_unix = 10;
    let mut second = completed(PhaseAttemptOutcome::Completed);
    second.attempt_id = "phase-a-second".to_string();
    second.completed_at_unix = 10;
    let snapshot = second.target_snapshot.clone();
    let ledger = PhaseAttemptLedger::from_events([
        PhaseAttemptEvent::PhaseAttemptCompleted(first),
        PhaseAttemptEvent::PhaseAttemptCompleted(second),
    ])
    .unwrap();

    assert_eq!(
        ledger
            .unresolved_for(WorkflowPhase::Scan, &snapshot)
            .map(|record| record.completed.attempt_id.as_str()),
        Some("phase-a-second")
    );
}

#[test]
fn same_second_selections_follow_disposition_append_order() {
    let mut first = completed(PhaseAttemptOutcome::Completed);
    first.attempt_id = "phase-z-first".to_string();
    let mut second = completed(PhaseAttemptOutcome::Completed);
    second.attempt_id = "phase-a-second".to_string();
    let snapshot = second.target_snapshot.clone();
    let mut first_selected = PhaseAttemptDispositionRecorded::new(
        &first.attempt_id,
        PhaseAttemptDisposition::Selected {
            acknowledged_partial: false,
        },
    );
    first_selected.recorded_at_unix = 20;
    let mut second_selected = PhaseAttemptDispositionRecorded::new(
        &second.attempt_id,
        PhaseAttemptDisposition::Selected {
            acknowledged_partial: false,
        },
    );
    second_selected.recorded_at_unix = 20;
    let ledger = PhaseAttemptLedger::from_events([
        PhaseAttemptEvent::PhaseAttemptCompleted(first),
        PhaseAttemptEvent::PhaseAttemptCompleted(second),
        PhaseAttemptEvent::PhaseAttemptDispositionRecorded(first_selected),
        PhaseAttemptEvent::PhaseAttemptDispositionRecorded(second_selected),
    ])
    .unwrap();

    assert_eq!(
        ledger
            .selected_for(WorkflowPhase::Scan, &snapshot)
            .map(|record| record.completed.attempt_id.as_str()),
        Some("phase-a-second")
    );
}

#[test]
fn partial_selection_requires_explicit_acknowledgement() {
    let target = tempfile::tempdir().unwrap();
    let attempt = completed(PhaseAttemptOutcome::Partial);
    append_phase_attempt_completed(target.path(), attempt.clone()).unwrap();
    let error = append_phase_attempt_disposition(
        target.path(),
        PhaseAttemptDispositionRecorded::new(
            attempt.attempt_id,
            PhaseAttemptDisposition::Selected {
                acknowledged_partial: false,
            },
        ),
    )
    .unwrap_err();
    assert!(error.to_string().contains("explicitly acknowledged"));
}

#[test]
fn evidence_blocked_partial_attempt_cannot_be_selected_even_when_acknowledged() {
    let target = tempfile::tempdir().unwrap();
    let reason = "No analyzable evidence found under /target";
    let attempt = completed(PhaseAttemptOutcome::Partial).with_selection_blocked(reason);
    append_phase_attempt_completed(target.path(), attempt.clone()).unwrap();

    let error = append_phase_attempt_disposition(
        target.path(),
        PhaseAttemptDispositionRecorded::new(
            attempt.attempt_id,
            PhaseAttemptDisposition::Selected {
                acknowledged_partial: true,
            },
        ),
    )
    .unwrap_err();

    assert!(error.to_string().contains(reason), "{error:#}");
}

#[test]
fn selection_blockers_are_rejected_on_non_partial_attempts() {
    let target = tempfile::tempdir().unwrap();
    let attempt =
        completed(PhaseAttemptOutcome::Completed).with_selection_blocked("unexpected blocker");

    let error = append_phase_attempt_completed(target.path(), attempt).unwrap_err();

    assert!(error.to_string().contains("only a partial"), "{error:#}");
}

#[test]
fn failed_attempt_can_be_discarded_but_not_selected() {
    let target = tempfile::tempdir().unwrap();
    let attempt = completed(PhaseAttemptOutcome::Failed);
    append_phase_attempt_completed(target.path(), attempt.clone()).unwrap();
    let selected = PhaseAttemptDispositionRecorded::new(
        &attempt.attempt_id,
        PhaseAttemptDisposition::Selected {
            acknowledged_partial: false,
        },
    );
    assert!(append_phase_attempt_disposition(target.path(), selected).is_err());
    append_phase_attempt_disposition(
        target.path(),
        PhaseAttemptDispositionRecorded::new(
            attempt.attempt_id,
            PhaseAttemptDisposition::Discarded,
        ),
    )
    .unwrap();
}

#[test]
fn discarding_never_deletes_the_completed_event() {
    let target = tempfile::tempdir().unwrap();
    let attempt = completed(PhaseAttemptOutcome::Completed);
    append_phase_attempt_completed(target.path(), attempt.clone()).unwrap();
    append_phase_attempt_disposition(
        target.path(),
        PhaseAttemptDispositionRecorded::new(
            &attempt.attempt_id,
            PhaseAttemptDisposition::Discarded,
        ),
    )
    .unwrap();

    let events = load_phase_attempt_events(target.path()).unwrap();
    assert_eq!(events.len(), 2);
    let ledger = PhaseAttemptLedger::from_events(events).unwrap();
    assert_eq!(
        ledger.attempt(&attempt.attempt_id).unwrap().completed,
        attempt
    );
}

#[test]
fn target_attempt_presence_survives_revision_changes_and_disposition() {
    let target = tempfile::tempdir().unwrap();
    let attempt = completed(PhaseAttemptOutcome::Completed);
    append_phase_attempt_completed(target.path(), attempt.clone()).unwrap();
    append_phase_attempt_disposition(
        target.path(),
        PhaseAttemptDispositionRecorded::new(
            &attempt.attempt_id,
            PhaseAttemptDisposition::Discarded,
        ),
    )
    .unwrap();

    let ledger = load_phase_attempt_ledger(target.path()).unwrap();
    let later_revision = PhaseTargetSnapshot {
        revision: Some("def".to_string()),
        ..attempt.target_snapshot.clone()
    };
    assert!(ledger.has_attempt_for_target(WorkflowPhase::Scan, &later_revision));
    assert!(!ledger.has_attempt_for_target(WorkflowPhase::Map, &later_revision));
    assert!(!ledger.has_attempt_for_target(
        WorkflowPhase::Scan,
        &PhaseTargetSnapshot {
            target: "/other-target".to_string(),
            ..later_revision
        }
    ));
}

#[test]
fn explicit_phase_skip_survives_restart_for_only_the_exact_snapshot() {
    let target = tempfile::tempdir().unwrap();
    let snapshot = PhaseTargetSnapshot {
        target: "/target".to_string(),
        revision: Some("abc".to_string()),
        dirty: false,
    };
    append_phase_checkpoint_skipped(
        target.path(),
        PhaseCheckpointSkipped::new(WorkflowPhase::Map, snapshot.clone()),
    )
    .unwrap();

    let ledger = load_phase_attempt_ledger(target.path()).unwrap();
    assert!(ledger.phase_was_skipped(WorkflowPhase::Map, &snapshot));
    assert_eq!(
        ledger.skipped_phases_for(&snapshot),
        BTreeSet::from([WorkflowPhase::Map])
    );
    let stale_snapshot = PhaseTargetSnapshot {
        revision: Some("def".to_string()),
        ..snapshot
    };
    assert!(!ledger.phase_was_skipped(WorkflowPhase::Map, &stale_snapshot));
}

#[test]
fn proof_deferral_survives_restart_for_only_the_exact_finding_generation() {
    let target = tempfile::tempdir().unwrap();
    let snapshot = PhaseTargetSnapshot {
        target: "/target".to_string(),
        revision: Some("abc".to_string()),
        dirty: false,
    };
    append_proof_deferral(
        target.path(),
        ProofDeferralRecorded::human(
            "finding-fp",
            Some("stable-fp".to_string()),
            "scan-1",
            snapshot.clone(),
            "runtime harness is unavailable in this environment",
        ),
    )
    .unwrap();

    let ledger = load_phase_attempt_ledger(target.path()).unwrap();
    assert!(ledger.proof_is_deferred_for(
        &snapshot,
        "new-fingerprint",
        Some("stable-fp"),
        "scan-1"
    ));
    assert!(!ledger.proof_is_deferred_for(
        &snapshot,
        "finding-fp",
        Some("stable-fp"),
        "scan-2"
    ));
    assert!(!ledger.proof_is_deferred_for(
        &PhaseTargetSnapshot {
            revision: Some("def".to_string()),
            ..snapshot
        },
        "finding-fp",
        Some("stable-fp"),
        "scan-1"
    ));
}

#[test]
fn proof_deferral_requires_a_durable_generation_and_reason() {
    let target = tempfile::tempdir().unwrap();
    let snapshot = PhaseTargetSnapshot {
        target: "/target".to_string(),
        revision: None,
        dirty: false,
    };
    for (scan_id, reason) in [("", "reason"), ("scan-1", "  ")] {
        let error = append_proof_deferral(
            target.path(),
            ProofDeferralRecorded::human("finding-fp", None, scan_id, snapshot.clone(), reason),
        )
        .unwrap_err();
        assert!(error.to_string().contains("proof deferral"));
    }
}
