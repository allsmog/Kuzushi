use super::*;
use crate::run_artifacts::RunSummary;
use crate::run_artifacts::ToolRunRecord;
use crate::run_lifecycle::{
    FindingDeltaSummary, OperatorDecisionValue, RunAttemptId, RunItemId, RunItemRecord,
    RunItemSource, RunItemStatus, RunItemV1, RunItemWriter, RunObservationHandle, RunQuestionId,
    SafeText, WorkflowContinuation,
};
use crate::runtime::RuntimeCostReport;
use crate::WorkflowPhase;
use crate::{ApplicationToolCall, WorkspaceTarget};
use std::collections::BTreeSet;
use std::fs;
use std::process::Command;

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
        changed_artifacts: vec!["result.json".to_string(), "items.jsonl".to_string()],
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

fn typed_completed(target: &std::path::Path) -> PhaseAttemptCompleted {
    let run_id = typed_run(target);
    PhaseAttemptCompleted::new(
        WorkflowPhase::Scan,
        vec![run_id],
        PhaseTargetSnapshot::capture(target),
        PhaseAttemptOutcome::Completed,
    )
    .with_attempt_id(RunAttemptId::new().to_string())
    .with_receipt(receipt())
}

fn typed_run(target: &std::path::Path) -> String {
    typed_run_with_status(target, RunItemStatus::Completed)
}

fn typed_run_with_status(target: &std::path::Path, status: RunItemStatus) -> String {
    let run_id = crate::run_artifacts::new_run_id("phase-v2");
    let target_name = target
        .canonicalize()
        .unwrap_or_else(|_| target.to_path_buf())
        .display()
        .to_string();
    let mut summary = RunSummary::running(
        &run_id,
        "tool",
        Some("fixture:run".to_string()),
        target_name,
    );
    summary.status = status.label().to_string();
    summary.completed_at_unix = Some(summary.started_at_unix);
    crate::run_artifacts::write_run_summary(
        target,
        &summary,
    )
    .unwrap();
    let writer = RunItemWriter::open(target, &run_id, None).unwrap();
    writer
        .emit_and_flush(RunItemRecord::new(
            RunItemId::new(),
            RunItemSource::Workflow,
            RunItemV1::TerminalOutcome {
                status,
                summary: SafeText::operator_visible(format!(
                    "phase run {}",
                    status.label()
                )),
                cost: RuntimeCostReport::UNAVAILABLE,
                continuation: WorkflowContinuation::NoFurtherAction {
                    reason: SafeText::operator_visible("await phase receipt"),
                },
            },
        ))
        .unwrap();
    writer.shutdown().unwrap();
    run_id
}

fn indexed_typed_completed(target: &std::path::Path) -> PhaseAttemptCompleted {
    let workspace = WorkspaceTarget::new(target).unwrap();
    let indexed = crate::incremental_index::index_workspace_snapshot(&workspace).unwrap();
    let run_id = crate::run_artifacts::new_run_id("phase-indexed-v2");
    let input = serde_json::json!({"target": workspace.root()});
    let record = ToolRunRecord::new(target, &run_id, "tool", "fixture:indexed");
    crate::run_artifacts::try_record_tool_run_started_with_reproducibility(
        record,
        &input,
        None,
        None,
        Vec::new(),
    )
    .unwrap();
    let observation = RunObservationHandle::jsonl(target, &run_id)
        .unwrap()
        .start_root_task("Index the accepted target")
        .unwrap();
    observation
        .task_handle()
        .unwrap()
        .update_and_flush(RunItemStatus::Running, None)
        .unwrap();
    let call =
        ApplicationToolCall::start(observation.clone(), "fixture:indexed", &input, None, None)
            .unwrap();
    let output = serde_json::json!({
        "status": "completed",
        "summary": "indexed fixture complete",
        "data": {"snapshot": {
            "snapshotHash": indexed.snapshot_hash,
            "treeHash": indexed.tree_hash,
        }},
    });
    let completion = call.completion_from_result(&Ok(output.clone()));
    crate::run_artifacts::try_record_tool_run_complete_settled(
        record,
        &output,
        &observation,
        completion,
    )
    .unwrap();
    PhaseAttemptCompleted::new(
        WorkflowPhase::Scan,
        vec![run_id],
        PhaseTargetSnapshot::capture(target),
        PhaseAttemptOutcome::Completed,
    )
    .with_attempt_id(RunAttemptId::new().to_string())
    .with_receipt(receipt())
}

fn typed_receipt_truth_attempt(target: &std::path::Path) -> PhaseAttemptCompleted {
    let run_id = crate::run_artifacts::new_run_id("phase-receipt-truth");
    let record = ToolRunRecord::new(target, &run_id, "tool", "fixture:receipt-truth");
    crate::run_artifacts::try_record_tool_run_started_with_reproducibility(
        record,
        &serde_json::json!({}),
        None,
        None,
        Vec::new(),
    )
    .unwrap();
    let observation = RunObservationHandle::jsonl(target, &run_id)
        .unwrap()
        .start_root_task("Preserve typed receipt truth")
        .unwrap();
    observation
        .task_handle()
        .unwrap()
        .update_and_flush(RunItemStatus::Running, None)
        .unwrap();
    let input = serde_json::json!({"scope": "fixture"});
    let call = ApplicationToolCall::start(
        observation.clone(),
        "fixture:receipt-truth",
        &input,
        None,
        None,
    )
    .unwrap();
    emit_receipt_truth(&observation);
    let output = receipt_truth_output();
    let completion = call.completion_from_result(&Ok(output.clone()));
    crate::run_artifacts::try_record_tool_run_complete_settled(
        record,
        &output,
        &observation,
        completion,
    )
    .unwrap();
    PhaseAttemptCompleted::new(
        WorkflowPhase::Scan,
        vec![run_id],
        PhaseTargetSnapshot::capture(target),
        PhaseAttemptOutcome::Completed,
    )
    .with_attempt_id(RunAttemptId::new().to_string())
    .with_receipt(contradictory_receipt())
}

fn emit_receipt_truth(observation: &RunObservationHandle) {
    let question_id = RunQuestionId::new();
    let question_item_id = RunItemId::new();
    let authorization_scope = SafeText::operator_visible("fixture decision");
    let records = [
        (
            question_item_id,
            RunItemV1::OperatorQuestion {
                question_id,
                prompt: SafeText::operator_visible("Continue with fixture evidence?"),
                choices: Vec::new(),
                authorization_scope: authorization_scope.clone(),
            },
        ),
        (
            question_item_id,
            RunItemV1::OperatorDecision {
                question_id,
                decision: OperatorDecisionValue::Approved,
                authorization_scope,
            },
        ),
        (
            RunItemId::new(),
            RunItemV1::FindingDelta {
                delta: FindingDeltaSummary {
                    added: 2,
                    updated: 1,
                    removed: 1,
                    store_watermark: SafeText::operator_visible("fixture:4"),
                    finding_id_samples: Vec::new(),
                },
            },
        ),
    ];
    for (item_id, item) in records {
        observation
            .emit_and_flush(RunItemRecord::new(
                item_id,
                RunItemSource::Workflow,
                item,
            ))
            .unwrap();
    }
}

fn receipt_truth_output() -> serde_json::Value {
    serde_json::json!({
        "status": "completed",
        "summary": "typed receipt truth",
        "costUsd": 0.25,
        "data": {"costUsd": 0.25, "evidence": "fixture"},
    })
}

fn contradictory_receipt() -> PhaseAttemptReceipt {
    PhaseAttemptReceipt {
        run_count: 99,
        elapsed_secs: 17,
        cost: "$99.0000".to_string(),
        changed_findings: 99,
        changed_artifacts: vec!["transient-guessed.json".to_string()],
        interaction_count: 99,
        rerun_specification: Some("preserve compatibility-only rerun input".to_string()),
        actions: vec![PhaseResultAction::Discard],
        recommended_next: Some("transient next".to_string()),
    }
}

fn attach_snapshot_result(
    target: &std::path::Path,
    run_id: &str,
    snapshot_hash: &str,
    tree_hash: &str,
) {
    let value = serde_json::json!({
        "data": {
            "snapshot": {
                "snapshotHash": snapshot_hash,
                "treeHash": tree_hash,
            }
        }
    });
    let path = crate::run_artifacts::run_artifact_path(target, run_id, "result.json");
    fs::write(path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
}

fn init_clean_git_target(target: &std::path::Path) -> bool {
    if Command::new("git").arg("--version").output().is_err() {
        return false;
    }
    let commands = [
        vec!["init", "--quiet"],
        vec!["config", "user.email", "kuzushi-tests@example.invalid"],
        vec!["config", "user.name", "Kuzushi Tests"],
        vec!["add", "fixture.txt"],
        vec!["commit", "--quiet", "-m", "fixture"],
    ];
    fs::write(target.join("fixture.txt"), "before\n").unwrap();
    commands.into_iter().all(|args| {
        Command::new("git")
            .args(args)
            .current_dir(target)
            .status()
            .is_ok_and(|status| status.success())
    })
}

fn git_sha(target: &std::path::Path) -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(target)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn commit_fixture(target: &std::path::Path, contents: &str, message: &str) -> bool {
    fs::write(target.join("fixture.txt"), contents).unwrap();
    Command::new("git")
        .args(["add", "fixture.txt"])
        .current_dir(target)
        .status()
        .is_ok_and(|status| status.success())
        && Command::new("git")
            .args(["commit", "--quiet", "-m", message])
            .current_dir(target)
            .status()
            .is_ok_and(|status| status.success())
}

fn rewrite_run_target(target: &std::path::Path, run_id: &str, run_target: &str) {
    let path = crate::run_artifacts::run_artifact_path(target, run_id, "run.json");
    let mut summary: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    summary["target"] = serde_json::Value::String(run_target.to_string());
    fs::write(path, serde_json::to_vec_pretty(&summary).unwrap()).unwrap();
}

fn rewrite_jsonl_string(path: &std::path::Path, pointer: &str, replacement: &str) {
    let mut changed = false;
    let lines = fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| {
            let mut value: serde_json::Value = serde_json::from_str(line).unwrap();
            if let Some(slot) = value.pointer_mut(pointer) {
                *slot = serde_json::Value::String(replacement.to_string());
                changed = true;
            }
            serde_json::to_string(&value).unwrap()
        })
        .collect::<Vec<_>>();
    assert!(changed, "missing JSON pointer {pointer} in {}", path.display());
    fs::write(path, format!("{}\n", lines.join("\n"))).unwrap();
}

#[test]
fn workflow_v2_dual_writes_reference_only_receipts_and_v1_projection() {
    let target = tempfile::tempdir().unwrap();
    let attempt = typed_completed(target.path());

    append_phase_attempt_completed_with_v2(target.path(), attempt.clone()).unwrap();

    let v2 = load_phase_attempt_ledger_v2(target.path()).unwrap();
    let typed_id = RunAttemptId::parse(&attempt.attempt_id).unwrap();
    let completed = &v2.attempts[&typed_id];
    assert_eq!(completed.run_refs.len(), 1);
    assert!(matches!(
        completed.target_content_identity,
        TargetContentIdentity::Unavailable { .. }
    ));
    let v1 = load_phase_attempt_events(target.path()).unwrap();
    assert_eq!(v1.len(), 1);
    let body = fs::read_to_string(phase_attempt_v2_ledger_path(target.path())).unwrap();
    assert!(!body.contains("phase run complete"));
    assert!(!body.contains("result.json"));
}

#[test]
fn blocked_phase_attempt_stays_blocked_in_v1_v2_and_typed_receipt() {
    let target = tempfile::tempdir().unwrap();
    let run_id = typed_run_with_status(target.path(), RunItemStatus::Blocked);
    let attempt = PhaseAttemptCompleted::new(
        WorkflowPhase::Scan,
        vec![run_id.clone()],
        PhaseTargetSnapshot::capture(target.path()),
        PhaseAttemptOutcome::Blocked,
    )
    .with_attempt_id(RunAttemptId::new().to_string())
    .with_receipt(receipt());

    append_phase_attempt_completed_with_v2(target.path(), attempt.clone()).unwrap();

    let typed_id = RunAttemptId::parse(&attempt.attempt_id).unwrap();
    let v2 = load_phase_attempt_ledger_v2(target.path()).unwrap();
    assert_eq!(v2.attempts[&typed_id].outcome, RunItemStatus::Blocked);
    let receipt = crate::workflow_attempts::load_phase_receipt_projection_v2(
        target.path(),
        &attempt.attempt_id,
    )
    .unwrap()
    .unwrap();
    assert_eq!(receipt.status, RunItemStatus::Blocked);
    assert!(receipt
        .offered_actions
        .iter()
        .all(|action| !matches!(
            action,
            WorkflowContinuation::OpenPhase { .. }
                | WorkflowContinuation::OpenReport { .. }
                | WorkflowContinuation::NoFurtherAction { .. }
        )));
    let events = load_phase_attempt_events(target.path()).unwrap();
    let PhaseAttemptEvent::PhaseAttemptCompleted(v1) = &events[0] else {
        panic!("expected workflow-v1 completion");
    };
    assert_eq!(v1.outcome, PhaseAttemptOutcome::Blocked);
    assert_eq!(v1.run_refs, vec![run_id]);
}

#[test]
fn workflow_v2_legacy_projection_uses_typed_receipt_truth() {
    let target = tempfile::tempdir().unwrap();
    let attempt = typed_receipt_truth_attempt(target.path());
    let before = crate::run_lifecycle::load_run_projection(target.path(), &attempt.run_refs[0])
        .unwrap()
        .projection;
    assert_eq!(
        before.health,
        crate::run_lifecycle::ProjectionHealth::Healthy,
        "fixture stream must be healthy before receipt projection"
    );
    let summary = crate::run_artifacts::load_run_summary(target.path(), &attempt.run_refs[0])
        .unwrap();
    assert!(
        summary
            .artifacts
            .iter()
            .any(|artifact| artifact.path.ends_with("result.json")),
        "fixture summary artifacts: {:?}",
        summary.artifacts
    );
    assert!(
        !before.artifacts.is_empty(),
        "fixture artifacts missing from timeline: {:?}",
        before.timeline
    );

    append_phase_attempt_completed_with_v2(target.path(), attempt.clone()).unwrap();

    let events = load_phase_attempt_events(target.path()).unwrap();
    let PhaseAttemptEvent::PhaseAttemptCompleted(completed) = &events[0] else {
        panic!("expected completed attempt");
    };
    let receipt = completed.receipt.as_ref().unwrap();
    assert_eq!(receipt.run_count, 1);
    assert_eq!(receipt.cost, "$0.2500 exact");
    assert_eq!(receipt.changed_findings, 4);
    assert_eq!(receipt.interaction_count, 1);
    assert!(receipt
        .changed_artifacts
        .iter()
        .any(|path| path.ends_with("result.json")),
        "typed artifact paths: {:?}",
        receipt.changed_artifacts
    );
    assert!(!receipt
        .changed_artifacts
        .iter()
        .any(|path| path.contains("transient-guessed")));
    assert_eq!(
        receipt.rerun_specification.as_deref(),
        Some("preserve compatibility-only rerun input")
    );
    assert!(receipt.actions.contains(&PhaseResultAction::SelectAndContinue));
    assert_eq!(receipt.recommended_next.as_deref(), Some("open REVIEW"));
}

#[test]
fn unavailable_dirty_identity_blocks_cross_attempt_reuse_without_losing_history() {
    let target = tempfile::tempdir().unwrap();
    let attempt = typed_completed(target.path());
    append_phase_attempt_completed_with_v2(target.path(), attempt.clone()).unwrap();
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

    let recovered = load_phase_attempt_ledger_recovering(target.path()).unwrap();
    assert!(recovered.ledger.attempt(&attempt.attempt_id).is_some());
    assert!(recovered
        .ledger
        .content_reuse_is_blocked(&attempt.attempt_id));
    assert!(recovered
        .ledger
        .selected_for(WorkflowPhase::Scan, &attempt.target_snapshot)
        .is_none());
    assert!(recovered
        .ledger
        .latest_selected_history_for_target(WorkflowPhase::Scan, &attempt.target_snapshot)
        .is_none());
}

#[test]
fn indexed_snapshot_reuses_non_git_evidence_only_while_source_matches() {
    let target = tempfile::tempdir().unwrap();
    fs::write(target.path().join("fixture.rs"), "fn before() {}\n").unwrap();
    let attempt = indexed_typed_completed(target.path());
    append_phase_attempt_completed_with_v2(target.path(), attempt.clone()).unwrap();
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

    let before = load_phase_attempt_ledger(target.path()).unwrap();
    assert!(
        before
            .selected_for(WorkflowPhase::Scan, &attempt.target_snapshot)
            .is_some(),
        "stored={:?}; requested={:?}; current_tree={:?}; identity={:?}",
        before.attempt(&attempt.attempt_id),
        attempt.target_snapshot,
        crate::incremental_index::current_workspace_tree_hash(target.path()),
        referenced_run_content_identity(target.path(), &attempt.run_refs),
    );

    fs::write(target.path().join("fixture.rs"), "fn after() {}\n").unwrap();
    let after = load_phase_attempt_ledger_recovering(target.path()).unwrap();
    assert!(after.ledger.content_reuse_is_blocked(&attempt.attempt_id));
    assert!(after
        .ledger
        .selected_for(WorkflowPhase::Scan, &attempt.target_snapshot)
        .is_none());
    assert_eq!(
        after
            .ledger
            .latest_selected_history_for_target(
                WorkflowPhase::Scan,
                &PhaseTargetSnapshot::capture(target.path()),
            )
            .map(|record| record.completed.attempt_id.as_str()),
        Some(attempt.attempt_id.as_str()),
        "authenticated historical selection remains available for drift disclosure"
    );
}

#[cfg(unix)]
#[test]
fn referenced_target_symlink_is_stored_as_the_canonical_target_identity() {
    use std::os::unix::fs::symlink;

    let fixture = tempfile::tempdir().unwrap();
    let target = fixture.path().join("target");
    let alias = fixture.path().join("target-alias");
    fs::create_dir(&target).unwrap();
    fs::write(target.join("fixture.rs"), "fn fixture() {}\n").unwrap();
    symlink(&target, &alias).unwrap();
    let attempt = indexed_typed_completed(&target);
    rewrite_run_target(&target, &attempt.run_refs[0], &alias.display().to_string());

    append_phase_attempt_completed_with_v2(&target, attempt.clone()).unwrap();
    append_phase_attempt_disposition(
        &target,
        PhaseAttemptDispositionRecorded::new(
            &attempt.attempt_id,
            PhaseAttemptDisposition::Selected {
                acknowledged_partial: false,
            },
        ),
    )
    .unwrap();

    let expected = PhaseTargetSnapshot::capture(&target);
    let ledger = load_phase_attempt_ledger(&target).unwrap();
    let stored = ledger.attempt(&attempt.attempt_id).unwrap();
    assert_eq!(stored.completed.target_snapshot, expected);
    assert!(ledger.selected_for(WorkflowPhase::Scan, &expected).is_some());
}

#[cfg(unix)]
#[test]
fn precanonical_target_alias_remains_reusable_without_rewriting_ledgers() {
    use std::os::unix::fs::symlink;

    let fixture = tempfile::tempdir().unwrap();
    let target = fixture.path().join("target");
    let alias = fixture.path().join("target-alias");
    fs::create_dir(&target).unwrap();
    fs::write(target.join("fixture.rs"), "fn fixture() {}\n").unwrap();
    symlink(&target, &alias).unwrap();
    let attempt = indexed_typed_completed(&target);
    let alias = alias.display().to_string();
    rewrite_run_target(&target, &attempt.run_refs[0], &alias);
    append_phase_attempt_completed_with_v2(&target, attempt.clone()).unwrap();
    append_phase_attempt_disposition(
        &target,
        PhaseAttemptDispositionRecorded::new(
            &attempt.attempt_id,
            PhaseAttemptDisposition::Selected {
                acknowledged_partial: false,
            },
        ),
    )
    .unwrap();
    let legacy_path = phase_attempt_ledger_path(&target);
    let v2_path = phase_attempt_v2_ledger_path(&target);
    rewrite_jsonl_string(&legacy_path, "/targetSnapshot/target", &alias);
    rewrite_jsonl_string(&v2_path, "/record/target", &alias);
    let before = (fs::read(&legacy_path).unwrap(), fs::read(&v2_path).unwrap());

    let recovered = load_phase_attempt_ledger_recovering(&target).unwrap();
    let expected = PhaseTargetSnapshot::capture(&target);
    assert!(!recovered.is_degraded(), "{:?}", recovered.degraded_reason);
    assert!(recovered
        .ledger
        .selected_for(WorkflowPhase::Scan, &expected)
        .is_some());
    assert_eq!(fs::read(&legacy_path).unwrap(), before.0);
    assert_eq!(fs::read(&v2_path).unwrap(), before.1);
}

#[test]
fn clean_commit_receipt_stays_referenced_but_reuse_stops_after_mutation() {
    let target = tempfile::tempdir().unwrap();
    if !init_clean_git_target(target.path()) {
        return;
    }
    let attempt = typed_completed(target.path());
    append_phase_attempt_completed_with_v2(target.path(), attempt.clone()).unwrap();
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
    let before = load_phase_attempt_ledger(target.path()).unwrap();
    assert!(before
        .selected_for(WorkflowPhase::Scan, &attempt.target_snapshot)
        .is_some());

    fs::write(target.path().join("fixture.txt"), "after\n").unwrap();

    let after = load_phase_attempt_ledger_recovering(target.path()).unwrap();
    assert!(after.ledger.attempt(&attempt.attempt_id).is_some());
    assert!(after.ledger.content_reuse_is_blocked(&attempt.attempt_id));
    assert!(after
        .ledger
        .selected_for(WorkflowPhase::Scan, &attempt.target_snapshot)
        .is_none());
    assert_eq!(
        after
            .ledger
            .latest_selected_history_for_target(
                WorkflowPhase::Scan,
                &PhaseTargetSnapshot::capture(target.path()),
            )
            .map(|record| record.completed.attempt_id.as_str()),
        Some(attempt.attempt_id.as_str()),
        "commit drift remains presentational history, never current truth"
    );
}

#[test]
fn clean_commit_identity_uses_run_start_revision_when_target_changes_before_receipt() {
    let target = tempfile::tempdir().unwrap();
    if !init_clean_git_target(target.path()) {
        return;
    }
    let start_revision = git_sha(target.path()).unwrap();
    let attempt = typed_completed(target.path());
    assert!(commit_fixture(target.path(), "after\n", "after run"));
    assert_ne!(
        git_sha(target.path()).as_deref(),
        Some(start_revision.as_str())
    );
    assert_eq!(
        referenced_run_content_identity(target.path(), &attempt.run_refs),
        TargetContentIdentity::CleanGitCommit {
            commit: SafeText::operator_visible(&start_revision),
        }
    );

    append_phase_attempt_completed_with_v2(target.path(), attempt.clone()).unwrap();

    let typed_id = RunAttemptId::parse(&attempt.attempt_id).unwrap();
    let v2 = load_phase_attempt_ledger_v2(target.path()).unwrap();
    assert_eq!(
        v2.attempts[&typed_id].target_content_identity,
        TargetContentIdentity::CleanGitCommit {
            commit: SafeText::operator_visible(&start_revision),
        }
    );
    let events = load_phase_attempt_events(target.path()).unwrap();
    let PhaseAttemptEvent::PhaseAttemptCompleted(completed) = &events[0] else {
        panic!("expected completed attempt");
    };
    assert_eq!(
        completed.target_snapshot.revision.as_deref(),
        Some(start_revision.as_str())
    );
    assert!(!completed.target_snapshot.dirty);
}

#[test]
fn dirty_run_start_does_not_become_reusable_when_target_is_clean_before_receipt() {
    let target = tempfile::tempdir().unwrap();
    if !init_clean_git_target(target.path()) {
        return;
    }
    let start_revision = git_sha(target.path()).unwrap();
    fs::write(target.path().join("fixture.txt"), "dirty at start\n").unwrap();
    let attempt = typed_completed(target.path());
    assert!(commit_fixture(
        target.path(),
        "clean before receipt\n",
        "clean before receipt"
    ));

    append_phase_attempt_completed_with_v2(target.path(), attempt.clone()).unwrap();

    let typed_id = RunAttemptId::parse(&attempt.attempt_id).unwrap();
    let v2 = load_phase_attempt_ledger_v2(target.path()).unwrap();
    assert!(matches!(
        v2.attempts[&typed_id].target_content_identity,
        TargetContentIdentity::Unavailable { .. }
    ));
    let events = load_phase_attempt_events(target.path()).unwrap();
    let PhaseAttemptEvent::PhaseAttemptCompleted(completed) = &events[0] else {
        panic!("expected completed attempt");
    };
    assert_eq!(
        completed.target_snapshot.revision.as_deref(),
        Some(start_revision.as_str())
    );
    assert!(completed.target_snapshot.dirty);
    let recovered = load_phase_attempt_ledger_recovering(target.path()).unwrap();
    assert!(recovered
        .ledger
        .content_reuse_is_blocked(&attempt.attempt_id));
}

#[test]
fn legacy_v1_completion_snapshot_cannot_override_referenced_run_identity() {
    let target = tempfile::tempdir().unwrap();
    if !init_clean_git_target(target.path()) {
        return;
    }
    let run_id = typed_run(target.path());
    assert!(commit_fixture(
        target.path(),
        "after\n",
        "after referenced run"
    ));
    let completion_snapshot = PhaseTargetSnapshot::capture(target.path());
    let attempt = PhaseAttemptCompleted::new(
        WorkflowPhase::Scan,
        vec![run_id],
        completion_snapshot.clone(),
        PhaseAttemptOutcome::Completed,
    )
    .with_attempt_id("phase-legacy-unverifiable")
    .with_receipt(receipt());
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
    let ledger_path = phase_attempt_ledger_path(target.path());
    let before = fs::read(&ledger_path).unwrap();

    let recovered = load_phase_attempt_ledger_recovering(target.path()).unwrap();

    assert!(!recovered.is_degraded());
    assert!(recovered.ledger.attempt(&attempt.attempt_id).is_some());
    assert!(recovered
        .ledger
        .content_reuse_is_blocked(&attempt.attempt_id));
    assert!(recovered
        .ledger
        .selected_for(WorkflowPhase::Scan, &completion_snapshot)
        .is_none());
    assert_eq!(fs::read(&ledger_path).unwrap(), before);
    assert!(!phase_attempt_v2_ledger_path(target.path()).exists());
}

#[test]
fn referenced_clean_identity_keeps_matching_legacy_v1_attempt_reusable() {
    let target = tempfile::tempdir().unwrap();
    if !init_clean_git_target(target.path()) {
        return;
    }
    let mut attempt = typed_completed(target.path());
    attempt.attempt_id = "phase-legacy-verifiable".to_string();
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

    let recovered = load_phase_attempt_ledger_recovering(target.path()).unwrap();

    assert!(!recovered
        .ledger
        .content_reuse_is_blocked(&attempt.attempt_id));
    assert!(recovered
        .ledger
        .selected_for(WorkflowPhase::Scan, &attempt.target_snapshot)
        .is_some());
}

#[test]
fn mixed_referenced_run_commits_persist_history_but_block_reuse() {
    let target = tempfile::tempdir().unwrap();
    if !init_clean_git_target(target.path()) {
        return;
    }
    let first_run = typed_run(target.path());
    assert!(commit_fixture(target.path(), "second\n", "second revision"));
    let second_run = typed_run(target.path());
    let attempt = PhaseAttemptCompleted::new(
        WorkflowPhase::Scan,
        vec![first_run, second_run],
        PhaseTargetSnapshot::capture(target.path()),
        PhaseAttemptOutcome::Completed,
    )
    .with_attempt_id(RunAttemptId::new().to_string())
    .with_receipt(receipt());

    append_phase_attempt_completed_with_v2(target.path(), attempt.clone()).unwrap();

    let typed_id = RunAttemptId::parse(&attempt.attempt_id).unwrap();
    let v2 = load_phase_attempt_ledger_v2(target.path()).unwrap();
    assert!(matches!(
        v2.attempts[&typed_id].target_content_identity,
        TargetContentIdentity::Unavailable { .. }
    ));
    let recovered = load_phase_attempt_ledger_recovering(target.path()).unwrap();
    assert!(!recovered.is_degraded(), "{:?}", recovered.degraded_reason);
    assert!(recovered
        .ledger
        .content_reuse_is_blocked(&attempt.attempt_id));
    let stored = recovered.ledger.attempt(&attempt.attempt_id).unwrap();
    assert_eq!(stored.completed.target_snapshot.revision, None);
    assert!(stored.completed.target_snapshot.dirty);
}

#[test]
fn mixed_referenced_run_targets_persist_history_but_block_reuse() {
    let target = tempfile::tempdir().unwrap();
    let first_run = typed_run(target.path());
    let second_run = typed_run(target.path());
    rewrite_run_target(target.path(), &second_run, "/different-target");
    let attempt = PhaseAttemptCompleted::new(
        WorkflowPhase::Scan,
        vec![first_run, second_run],
        PhaseTargetSnapshot::capture(target.path()),
        PhaseAttemptOutcome::Completed,
    )
    .with_attempt_id(RunAttemptId::new().to_string())
    .with_receipt(receipt());

    append_phase_attempt_completed_with_v2(target.path(), attempt.clone()).unwrap();

    let typed_id = RunAttemptId::parse(&attempt.attempt_id).unwrap();
    let v2 = load_phase_attempt_ledger_v2(target.path()).unwrap();
    assert!(matches!(
        v2.attempts[&typed_id].target_content_identity,
        TargetContentIdentity::Unavailable { .. }
    ));
    assert!(v2.attempts[&typed_id]
        .target
        .as_str()
        .starts_with("<unavailable:"));
    let recovered = load_phase_attempt_ledger_recovering(target.path()).unwrap();
    assert!(!recovered.is_degraded(), "{:?}", recovered.degraded_reason);
    assert!(recovered
        .ledger
        .content_reuse_is_blocked(&attempt.attempt_id));
}

#[test]
fn mixed_indexed_snapshots_persist_history_but_block_reuse() {
    let target = tempfile::tempdir().unwrap();
    fs::write(target.path().join("fixture.rs"), "fn fixture() {}\n").unwrap();
    let first_run = typed_run(target.path());
    let second_run = typed_run(target.path());
    let tree_hash = crate::incremental_index::current_workspace_tree_hash(target.path()).unwrap();
    attach_snapshot_result(target.path(), &first_run, &"a".repeat(64), &tree_hash);
    attach_snapshot_result(target.path(), &second_run, &"b".repeat(64), &tree_hash);
    let attempt = PhaseAttemptCompleted::new(
        WorkflowPhase::Scan,
        vec![first_run, second_run],
        PhaseTargetSnapshot::capture(target.path()),
        PhaseAttemptOutcome::Completed,
    )
    .with_attempt_id(RunAttemptId::new().to_string())
    .with_receipt(receipt());

    append_phase_attempt_completed_with_v2(target.path(), attempt.clone()).unwrap();

    let typed_id = RunAttemptId::parse(&attempt.attempt_id).unwrap();
    let v2 = load_phase_attempt_ledger_v2(target.path()).unwrap();
    assert!(matches!(
        v2.attempts[&typed_id].target_content_identity,
        TargetContentIdentity::Unavailable { .. }
    ));
    let recovered = load_phase_attempt_ledger_recovering(target.path()).unwrap();
    assert!(!recovered.is_degraded(), "{:?}", recovered.degraded_reason);
    assert!(recovered
        .ledger
        .content_reuse_is_blocked(&attempt.attempt_id));
}

#[test]
fn unreferenced_invalid_result_does_not_override_clean_git_identity() {
    let target = tempfile::tempdir().unwrap();
    if !init_clean_git_target(target.path()) {
        return;
    }
    let attempt = typed_completed(target.path());
    let path =
        crate::run_artifacts::run_artifact_path(target.path(), &attempt.run_refs[0], "result.json");
    fs::write(
        path,
        serde_json::to_vec(&serde_json::json!({
            "data": {"snapshot": {"snapshotHash": "not-a-hash"}}
        }))
        .unwrap(),
    )
    .unwrap();

    append_phase_attempt_completed_with_v2(target.path(), attempt.clone()).unwrap();

    let typed_id = RunAttemptId::parse(&attempt.attempt_id).unwrap();
    let v2 = load_phase_attempt_ledger_v2(target.path()).unwrap();
    assert_eq!(
        v2.attempts[&typed_id].target_content_identity,
        TargetContentIdentity::CleanGitCommit {
            commit: SafeText::operator_visible(git_sha(target.path()).unwrap()),
        }
    );
    let recovered = load_phase_attempt_ledger_recovering(target.path()).unwrap();
    assert!(!recovered
        .ledger
        .content_reuse_is_blocked(&attempt.attempt_id));
}

#[test]
fn unreferenced_conflicting_result_does_not_override_clean_git_identity() {
    let target = tempfile::tempdir().unwrap();
    if !init_clean_git_target(target.path()) {
        return;
    }
    let attempt = typed_completed(target.path());
    let path =
        crate::run_artifacts::run_artifact_path(target.path(), &attempt.run_refs[0], "result.json");
    fs::write(
        path,
        serde_json::to_vec(&serde_json::json!({
            "data": {
                "snapshot": {"snapshotHash": "a".repeat(64)},
                "snapshotHash": "b".repeat(64),
            }
        }))
        .unwrap(),
    )
    .unwrap();

    append_phase_attempt_completed_with_v2(target.path(), attempt.clone()).unwrap();

    let typed_id = RunAttemptId::parse(&attempt.attempt_id).unwrap();
    let v2 = load_phase_attempt_ledger_v2(target.path()).unwrap();
    assert_eq!(
        v2.attempts[&typed_id].target_content_identity,
        TargetContentIdentity::CleanGitCommit {
            commit: SafeText::operator_visible(git_sha(target.path()).unwrap()),
        }
    );
    let recovered = load_phase_attempt_ledger_recovering(target.path()).unwrap();
    assert!(!recovered
        .ledger
        .content_reuse_is_blocked(&attempt.attempt_id));
}

#[cfg(unix)]
#[test]
fn unreferenced_symlink_result_does_not_override_clean_git_identity() {
    use std::os::unix::fs::symlink;

    let target = tempfile::tempdir().unwrap();
    if !init_clean_git_target(target.path()) {
        return;
    }
    let attempt = typed_completed(target.path());
    let result_path =
        crate::run_artifacts::run_artifact_path(target.path(), &attempt.run_refs[0], "result.json");
    if let Err(error) = fs::remove_file(&result_path) {
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    }
    let external = tempfile::NamedTempFile::new().unwrap();
    symlink(external.path(), &result_path).unwrap();

    assert_eq!(
        referenced_run_content_identity(target.path(), &attempt.run_refs),
        TargetContentIdentity::CleanGitCommit {
            commit: SafeText::operator_visible(git_sha(target.path()).unwrap()),
        }
    );
}

#[test]
fn tampered_correlated_snapshot_does_not_fall_back_to_clean_git_identity() {
    let target = tempfile::tempdir().unwrap();
    if !init_clean_git_target(target.path()) {
        return;
    }
    let attempt = indexed_typed_completed(target.path());
    let result_path =
        crate::run_artifacts::run_artifact_path(target.path(), &attempt.run_refs[0], "result.json");
    fs::write(result_path, b"{\"status\":\"completed\",\"data\":{}}\n").unwrap();

    assert!(matches!(
        referenced_run_content_identity(target.path(), &attempt.run_refs),
        TargetContentIdentity::Unavailable { .. }
    ));
}

#[test]
fn changed_referenced_identity_degrades_without_rewriting_attempt_history() {
    let target = tempfile::tempdir().unwrap();
    if !init_clean_git_target(target.path()) {
        return;
    }
    let attempt = typed_completed(target.path());
    append_phase_attempt_completed_with_v2(target.path(), attempt.clone()).unwrap();
    let run_path =
        crate::run_artifacts::run_artifact_path(target.path(), &attempt.run_refs[0], "run.json");
    let mut run: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&run_path).unwrap()).unwrap();
    run["targetGit"]["sha"] = serde_json::Value::String("0".repeat(40));
    fs::write(&run_path, serde_json::to_vec_pretty(&run).unwrap()).unwrap();
    let ledger_path = phase_attempt_v2_ledger_path(target.path());
    let before = fs::read(&ledger_path).unwrap();

    let recovered = load_phase_attempt_ledger_recovering(target.path()).unwrap();

    assert!(recovered.is_degraded());
    assert!(recovered
        .degraded_reason
        .as_deref()
        .is_some_and(|reason| reason.contains("content identity disagrees")));
    assert!(recovered
        .ledger
        .content_reuse_is_blocked(&attempt.attempt_id));
    assert_eq!(fs::read(&ledger_path).unwrap(), before);
}

#[test]
fn missing_referenced_metadata_degrades_without_rewriting_attempt_history() {
    let target = tempfile::tempdir().unwrap();
    if !init_clean_git_target(target.path()) {
        return;
    }
    let attempt = typed_completed(target.path());
    append_phase_attempt_completed_with_v2(target.path(), attempt.clone()).unwrap();
    let run_path =
        crate::run_artifacts::run_artifact_path(target.path(), &attempt.run_refs[0], "run.json");
    fs::remove_file(run_path).unwrap();
    let ledger_path = phase_attempt_v2_ledger_path(target.path());
    let before = fs::read(&ledger_path).unwrap();

    let recovered = load_phase_attempt_ledger_recovering(target.path()).unwrap();

    assert!(recovered.is_degraded());
    assert!(recovered
        .degraded_reason
        .as_deref()
        .is_some_and(|reason| reason.contains("content identity disagrees")));
    assert!(recovered
        .ledger
        .content_reuse_is_blocked(&attempt.attempt_id));
    assert_eq!(fs::read(&ledger_path).unwrap(), before);
}

#[test]
fn changed_phase_receipt_reference_degrades_recovery_instead_of_guessing() {
    let target = tempfile::tempdir().unwrap();
    let attempt = typed_completed(target.path());
    append_phase_attempt_completed_with_v2(target.path(), attempt.clone()).unwrap();
    let path = phase_attempt_v2_ledger_path(target.path());
    let mut value: serde_json::Value =
        serde_json::from_str(fs::read_to_string(&path).unwrap().lines().next().unwrap()).unwrap();
    value["record"]["finalReceipt"]["eventHash"] =
        serde_json::Value::String(format!("sha256:{}", "0".repeat(64)));
    fs::write(
        &path,
        format!("{}\n", serde_json::to_string(&value).unwrap()),
    )
    .unwrap();

    let recovered = load_phase_attempt_ledger_recovering(target.path()).unwrap();
    assert!(recovered.is_degraded());
    assert!(recovered
        .degraded_reason
        .as_deref()
        .is_some_and(|reason| reason.contains("event hash changed")));
    assert!(recovered
        .ledger
        .content_reuse_is_blocked(&attempt.attempt_id));
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
fn completed_receipts_keep_a_bounded_artifact_preview() {
    let target = tempfile::tempdir().unwrap();
    let mut attempt = completed(PhaseAttemptOutcome::Completed);
    attempt.receipt = Some(oversized_receipt());

    append_phase_attempt_completed(target.path(), attempt.clone()).unwrap();

    let restored = load_phase_attempt_ledger(target.path())
        .unwrap()
        .attempt(&attempt.attempt_id)
        .unwrap()
        .completed
        .receipt
        .clone()
        .unwrap();
    assert_eq!(restored.changed_artifacts.len(), 32);
    assert!(restored
        .changed_artifacts
        .iter()
        .all(|path| path.len() <= 512));
    assert!(restored
        .changed_artifacts
        .last()
        .unwrap()
        .contains("additional"));
    assert_eq!(restored.actions, vec![PhaseResultAction::Open]);
    assert!(restored.cost.len() <= 256);
    assert!(restored.rerun_specification.unwrap().len() <= 8 * 1024);
    assert!(restored.recommended_next.unwrap().len() <= 2 * 1024);
}

fn oversized_receipt() -> PhaseAttemptReceipt {
    PhaseAttemptReceipt {
        run_count: 1,
        elapsed_secs: 1,
        cost: "c".repeat(1_000),
        changed_findings: 0,
        changed_artifacts: (0..100)
            .map(|index| format!("artifact-{index}-{}", "x".repeat(2_000)))
            .collect(),
        interaction_count: 0,
        rerun_specification: Some("r".repeat(20_000)),
        actions: vec![PhaseResultAction::Open, PhaseResultAction::Open],
        recommended_next: Some("n".repeat(5_000)),
    }
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
    let valid =
        serde_json::to_string(&PhaseAttemptEvent::PhaseAttemptCompleted(attempt.clone())).unwrap();
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
    let valid =
        serde_json::to_string(&PhaseAttemptEvent::PhaseAttemptCompleted(attempt.clone())).unwrap();
    let path = phase_attempt_ledger_path(target.path());
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, format!("{valid}\nnot-json\n")).unwrap();

    let recovered = load_phase_attempt_ledger_recovering(target.path()).unwrap();

    assert!(recovered.is_degraded());
    assert_eq!(recovered.malformed_line, Some(2));
    assert!(recovered.ledger.attempt(&attempt.attempt_id).is_some());
}

#[test]
fn append_heals_a_torn_tail_left_by_a_killed_writer() {
    let target = tempfile::tempdir().unwrap();
    let first = completed(PhaseAttemptOutcome::Completed);
    append_phase_attempt_completed(target.path(), first.clone()).unwrap();
    let path = phase_attempt_ledger_path(target.path());
    let mut body = fs::read_to_string(&path).unwrap();
    body.push_str("{\"phaseAttemptCompleted\":{\"tor");
    fs::write(&path, body).unwrap();

    let second = completed(PhaseAttemptOutcome::Completed);
    append_phase_attempt_completed(target.path(), second.clone()).unwrap();

    // The strict loader succeeding proves the torn tail was truncated,
    // not appended after.
    let ledger = load_phase_attempt_ledger(target.path()).unwrap();
    assert!(ledger.attempt(&first.attempt_id).is_some());
    assert!(ledger.attempt(&second.attempt_id).is_some());
}

#[test]
fn append_refuses_a_newline_terminated_corrupt_line_as_real_corruption() {
    let target = tempfile::tempdir().unwrap();
    let first = completed(PhaseAttemptOutcome::Completed);
    append_phase_attempt_completed(target.path(), first).unwrap();
    let path = phase_attempt_ledger_path(target.path());
    let mut body = fs::read_to_string(&path).unwrap();
    body.push_str("not-json\n");
    fs::write(&path, &body).unwrap();

    let error = append_phase_attempt_completed(target.path(), completed(PhaseAttemptOutcome::Completed))
        .unwrap_err()
        .to_string();

    assert!(error.contains("Invalid workflow attempt event"), "{error}");
    assert_eq!(fs::read_to_string(&path).unwrap(), body);
}

#[test]
fn unverifiable_legacy_v1_selection_round_trips_as_history_without_reuse() {
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
    let stored = ledger.attempt(&attempt.attempt_id).unwrap();
    assert!(matches!(
        stored.disposition.as_ref().map(|value| &value.disposition),
        Some(PhaseAttemptDisposition::Selected { .. })
    ));
    assert!(ledger.content_reuse_is_blocked(&attempt.attempt_id));
    assert!(ledger
        .selected_for(WorkflowPhase::Scan, &attempt.target_snapshot)
        .is_none());
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
fn disposing_the_latest_attempt_does_not_resurface_an_older_result() {
    let mut older = completed(PhaseAttemptOutcome::Completed);
    older.attempt_id = "phase-older".to_string();
    older.completed_at_unix = 10;
    let mut latest = completed(PhaseAttemptOutcome::Partial);
    latest.attempt_id = "phase-latest".to_string();
    latest.completed_at_unix = 20;
    let snapshot = latest.target_snapshot.clone();
    let discarded = PhaseAttemptDispositionRecorded::new(
        &latest.attempt_id,
        PhaseAttemptDisposition::Discarded,
    );
    let ledger = PhaseAttemptLedger::from_events([
        PhaseAttemptEvent::PhaseAttemptCompleted(older),
        PhaseAttemptEvent::PhaseAttemptCompleted(latest),
        PhaseAttemptEvent::PhaseAttemptDispositionRecorded(discarded),
    ])
    .unwrap();

    assert!(ledger
        .unresolved_for(WorkflowPhase::Scan, &snapshot)
        .is_none());
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
fn blocked_attempt_can_be_discarded_but_not_selected() {
    let target = tempfile::tempdir().unwrap();
    let attempt = completed(PhaseAttemptOutcome::Blocked);
    append_phase_attempt_completed(target.path(), attempt.clone()).unwrap();

    let selected = PhaseAttemptDispositionRecorded::new(
        &attempt.attempt_id,
        PhaseAttemptDisposition::Selected {
            acknowledged_partial: false,
        },
    );
    let error = append_phase_attempt_disposition(target.path(), selected).unwrap_err();
    assert!(error.to_string().contains("blocked"), "{error:#}");

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
fn selected_target_history_discloses_stale_checkpoint_without_reusing_it() {
    let attempt = completed(PhaseAttemptOutcome::Completed);
    let selection = PhaseAttemptDispositionRecorded::new(
        &attempt.attempt_id,
        PhaseAttemptDisposition::Selected {
            acknowledged_partial: false,
        },
    );
    let current = PhaseTargetSnapshot {
        revision: Some("def".to_string()),
        dirty: true,
        ..attempt.target_snapshot.clone()
    };
    let ledger = PhaseAttemptLedger::from_events([
        PhaseAttemptEvent::PhaseAttemptCompleted(attempt.clone()),
        PhaseAttemptEvent::PhaseAttemptDispositionRecorded(selection),
    ])
    .unwrap();

    assert!(ledger.selected_for(WorkflowPhase::Scan, &current).is_none());
    assert_eq!(
        ledger
            .latest_selected_for_target(WorkflowPhase::Scan, &current)
            .map(|record| record.completed.attempt_id.as_str()),
        Some(attempt.attempt_id.as_str())
    );
    assert!(ledger
        .latest_selected_for_target(
            WorkflowPhase::Scan,
            &PhaseTargetSnapshot {
                target: "/other-target".to_string(),
                ..current.clone()
            }
        )
        .is_none());

    let mut blocked = ledger;
    blocked.block_content_reuse(&attempt.attempt_id);
    assert!(blocked
        .latest_selected_for_target(WorkflowPhase::Scan, &current)
        .is_none());
    assert!(blocked
        .latest_selected_history_for_target(WorkflowPhase::Scan, &current)
        .is_none());
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
    let deferral = ledger
        .proof_deferral_for(&snapshot, "new-fingerprint", Some("stable-fp"), "scan-1")
        .expect("durable deferral record");
    assert_eq!(
        deferral.reason,
        "runtime harness is unavailable in this environment"
    );
    assert_eq!(
        ledger.latest_proof_deferral_for(&snapshot),
        Some(deferral)
    );
    assert!(!ledger.proof_is_deferred_for(&snapshot, "finding-fp", Some("stable-fp"), "scan-2"));
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

/// Real fingerprints are `tool:rule:hash`; the colon is part of the durable
/// identity and must not be rejected as unsafe (that made deferral
/// impossible for every real finding).
#[test]
fn proof_deferral_accepts_real_colon_fingerprints() {
    let target = tempfile::tempdir().unwrap();
    let snapshot = PhaseTargetSnapshot {
        target: "/target".to_string(),
        revision: Some("abc".to_string()),
        dirty: false,
    };

    append_proof_deferral(
        target.path(),
        ProofDeferralRecorded::human(
            "secret-scan:aws-access-key-id:9867ad7c5595db25",
            None,
            "scan-1",
            snapshot.clone(),
            "credential rotates with the lab; deferred to phase 2",
        ),
    )
    .unwrap();

    let ledger = load_phase_attempt_ledger(target.path()).unwrap();
    assert!(ledger.proof_is_deferred_for(
        &snapshot,
        "secret-scan:aws-access-key-id:9867ad7c5595db25",
        None,
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

/// A reviewed finding, persisted the way any mode persists one, so the shared
/// deferral service is exercised against a real store rather than a stub.
fn confirmed_finding_workspace(root: &std::path::Path) -> (WorkspaceTarget, String) {
    use crate::findings::{
        Finding, FindingStore, ReviewDecision, ReviewDecisionVerdict, Severity, TriageAuthor,
    };
    let workspace = WorkspaceTarget::new(root).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store.record_run_started("scan-1", root, "running").unwrap();
    let finding = Finding::new_tool(
        "semgrep",
        "demo.rule",
        "src/lib.rs",
        12,
        None,
        Severity::High,
        "candidate",
    );
    let fingerprint = finding.fingerprint.clone();
    let id = store.insert_finding("scan-1", &finding).unwrap();
    store
        .append_user_review_decision(
            id,
            &ReviewDecision {
                verdict: ReviewDecisionVerdict::Confirmed,
                author: TriageAuthor::Human,
                confidence: 1.0,
                rationale: "reviewed the source and sink".to_string(),
                dismiss_reason: None,
                actor: Some("operator".to_string()),
            },
        )
        .unwrap();
    (workspace, fingerprint)
}

#[test]
fn record_proof_deferral_service_binds_the_decision_to_the_discovery_generation() {
    let target = tempfile::tempdir().unwrap();
    let (workspace, fingerprint) = confirmed_finding_workspace(target.path());

    let recorded = record_proof_deferral(
        &workspace,
        &ProofDeferralRequest {
            reference: fingerprint.clone(),
            reason: "  no runtime harness for this language yet  ".to_string(),
        },
    )
    .unwrap();

    assert_eq!(recorded.scan_id, "scan-1");
    assert_eq!(
        recorded.deferral.reason,
        "no runtime harness for this language yet",
        "the service trims the operator reason before it becomes durable"
    );
    let ledger = load_phase_attempt_ledger(target.path()).unwrap();
    assert!(ledger.proof_is_deferred_for(
        &PhaseTargetSnapshot::capture(target.path()),
        &fingerprint,
        None,
        "scan-1"
    ));
    assert!(
        !ledger.proof_is_deferred_for(
            &PhaseTargetSnapshot::capture(target.path()),
            &fingerprint,
            None,
            "scan-2"
        ),
        "a later observation must never inherit the decision"
    );
}

#[test]
fn record_proof_deferral_service_refuses_an_unreviewed_finding() {
    use crate::findings::{Finding, FindingStore, Severity};
    let target = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("scan-1", target.path(), "running")
        .unwrap();
    let finding = Finding::new_tool(
        "semgrep",
        "demo.rule",
        "src/lib.rs",
        12,
        None,
        Severity::High,
        "candidate",
    );
    store.insert_finding("scan-1", &finding).unwrap();

    let error = record_proof_deferral(
        &workspace,
        &ProofDeferralRequest {
            reference: finding.fingerprint.clone(),
            reason: "later".to_string(),
        },
    )
    .unwrap_err();

    assert!(
        error.to_string().contains("not review-actionable"),
        "{error}"
    );
    assert!(load_phase_attempt_ledger(target.path())
        .unwrap()
        .latest_proof_deferral_for(&PhaseTargetSnapshot::capture(target.path()))
        .is_none());
}

#[test]
fn proof_deferral_view_discloses_the_decision_without_any_proof_state() {
    let record = ProofDeferralRecorded::human(
        "semgrep:demo.rule:9867ad7c",
        Some("fi_stable".to_string()),
        "scan-7",
        PhaseTargetSnapshot {
            target: "/target".to_string(),
            revision: Some("abc".to_string()),
            dirty: false,
        },
        "runtime harness is unavailable in this environment",
    );

    let view = ProofDeferralView::from_record(&record);

    assert_eq!(view.subject, "fi_stable");
    assert_eq!(view.fingerprint, "semgrep:demo.rule:9867ad7c");
    assert_eq!(view.scan_id, "scan-7");
    assert_eq!(view.actor, "operator");
    assert_eq!(
        view.disclosure_line(),
        "proof deferred by operator at generation scan-7 · runtime harness is unavailable in this environment"
    );
}

#[test]
fn proof_deferral_view_for_finding_reads_only_the_matching_generation() {
    use crate::findings::{Finding, Severity};
    let target = tempfile::tempdir().unwrap();
    let (workspace, fingerprint) = confirmed_finding_workspace(target.path());
    record_proof_deferral(
        &workspace,
        &ProofDeferralRequest {
            reference: fingerprint.clone(),
            reason: "deferred to phase 2".to_string(),
        },
    )
    .unwrap();

    let mut finding = Finding::new_tool(
        "semgrep",
        "demo.rule",
        "src/lib.rs",
        12,
        None,
        Severity::High,
        "candidate",
    );
    finding.scan_id = Some("scan-1".to_string());
    let view = proof_deferral_view_for_finding(&workspace, &finding)
        .unwrap()
        .expect("the recorded deferral for this generation");
    assert_eq!(view.reason, "deferred to phase 2");

    finding.scan_id = Some("scan-2".to_string());
    assert!(proof_deferral_view_for_finding(&workspace, &finding)
        .unwrap()
        .is_none());
}
