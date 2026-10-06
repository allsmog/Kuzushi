use super::*;
use crate::run_artifacts::{record_tool_run_complete, record_tool_run_started, ToolRunRecord};
use crate::workflow_attempts::{
    load_phase_attempt_ledger, load_phase_attempt_ledger_recovering, phase_attempt_ledger_path,
    PhaseAttemptEvent, PhaseAttemptOutcome, PhaseTargetSnapshot,
};
use serde_json::json;

#[test]
fn referenced_map_source_requires_current_content_and_the_same_workspace() {
    let target = tempfile::tempdir().unwrap();
    let source = target.path().join("app.rs");
    std::fs::write(&source, "pub fn context() {}\n").unwrap();
    record_bound_context(target.path());
    let refs = vec!["context-source".into()];
    assert!(referenced_runs_match_current_source(target.path(), &refs));
    std::fs::write(&source, "pub fn changed() {}\n").unwrap();
    assert!(!referenced_runs_match_current_source(target.path(), &refs));
    let other = tempfile::tempdir().unwrap();
    assert!(!referenced_runs_match_current_source(other.path(), &refs));
    assert!(!referenced_runs_match_current_source(target.path(), &[]));
}

fn record_bound_context(root: &Path) {
    let record = ToolRunRecord::new(root, "context-source", "tool", "context:build");
    crate::run_artifacts::try_record_tool_run_started_with_reproducibility(
        record,
        &json!({}),
        None,
        None,
        Vec::new(),
    )
    .unwrap();
    let config = crate::V2Config::default();
    let workspace = crate::WorkspaceTarget::new(root).unwrap();
    let trace = crate::TraceHandle::jsonl(root, "context-source");
    let ctx = crate::ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: Some(&trace),
        cancellation: None,
        authorization: Default::default(),
    };
    let registry = crate::ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let prepared = registry
        .prepare_dispatch_input("context:build", json!({"enrichment":false}), &ctx, None)
        .unwrap();
    let observed = registry
        .dispatch_prepared_input_observed_with_runtime(prepared, &ctx, None)
        .unwrap();
    let output = observed.execution.unwrap();
    crate::run_artifacts::try_record_tool_run_complete_settled(
        record,
        &output,
        &trace.run_observation().unwrap(),
        observed.completion,
    )
    .unwrap();
}

fn completed_tool(target: &Path, run_id: &str, tool: &str) -> PhaseAttemptCompleted {
    let record = ToolRunRecord::new(target, run_id, "tool", tool);
    record_tool_run_started(record, &json!({}));
    record_tool_run_complete(record, &json!({"ok":true,"data":{"tool":tool}}));
    PhaseAttemptCompleted::new(
        WorkflowPhase::Prove,
        vec![run_id.to_string()],
        PhaseTargetSnapshot::capture(target),
        PhaseAttemptOutcome::Completed,
    )
    .with_attempt_id(RunAttemptId::new().to_string())
}

/// Simulate a pre-policy release without using the current writer's admission rules.
fn save_historical_attempt(target: &Path, mut completed: PhaseAttemptCompleted) {
    let attempt_id = RunAttemptId::parse(&completed.attempt_id).unwrap();
    let referenced = referenced_run_state(target, &completed.run_refs);
    completed.target_snapshot = referenced.target_snapshot;
    let receipt = emit_or_load_phase_receipt(target, &completed, attempt_id).unwrap();
    project_typed_receipt_to_legacy(target, &mut completed, &receipt).unwrap();
    append_v2_event(
        target,
        PhaseAttemptEventV2::Completed(
            completed_v2(&completed, receipt, referenced.content_identity).unwrap(),
        ),
    )
    .unwrap();
    let path = phase_attempt_ledger_path(target);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap();
    writeln!(
        file,
        "{}",
        serde_json::to_string(&PhaseAttemptEvent::PhaseAttemptCompleted(completed)).unwrap()
    )
    .unwrap();
}

#[test]
fn delta_less_run_projects_an_unmeasured_compatibility_receipt() {
    let target = tempfile::tempdir().unwrap();
    let mut completed = completed_tool(target.path(), "verify-no-delta", "verify:finding");
    let attempt_id = RunAttemptId::parse(&completed.attempt_id).unwrap();
    completed.target_snapshot =
        referenced_run_state(target.path(), &completed.run_refs).target_snapshot;
    let receipt = emit_or_load_phase_receipt(target.path(), &completed, attempt_id).unwrap();

    project_typed_receipt_to_legacy(target.path(), &mut completed, &receipt).unwrap();

    let receipt = completed.receipt.expect("projected compatibility receipt");
    assert_eq!(receipt.changed_findings, 0);
    assert_eq!(
        receipt.finding_delta_observed,
        Some(false),
        "a run without a typed finding commit must not read as a measured +0"
    );
}

#[test]
fn evidence_only_trace_cannot_create_a_phase_attempt() {
    let target = tempfile::tempdir().unwrap();
    let trace = completed_tool(target.path(), "trace-no-phase", "trace:expand");
    let error = append_phase_attempt_completed_with_v2(target.path(), trace.clone()).unwrap_err();
    assert!(error.to_string().contains("phase result"));
    assert!(
        crate::workflow_attempts::append_phase_attempt_completed(target.path(), trace).is_err()
    );
    assert!(!phase_attempt_ledger_path(target.path()).exists());
    assert!(!phase_attempt_v2_ledger_path(target.path()).exists());
}

#[test]
fn recovery_restores_pending_verification_without_rewriting_trace_history() {
    let target = tempfile::tempdir().unwrap();
    let verification = completed_tool(target.path(), "verify-prior", "verify:finding");
    let trace = completed_tool(target.path(), "trace-later", "trace:expand");
    save_historical_attempt(target.path(), verification.clone());
    save_historical_attempt(target.path(), trace.clone());
    let path = phase_attempt_ledger_path(target.path());
    let typed_path = phase_attempt_v2_ledger_path(target.path());
    let before = std::fs::read(&path).unwrap();
    let typed_before = std::fs::read(&typed_path).unwrap();
    let recovered = load_phase_attempt_ledger_recovering(target.path()).unwrap();
    let snapshot = PhaseTargetSnapshot::capture(target.path());
    let pending = recovered
        .ledger
        .unresolved_for(WorkflowPhase::Prove, &snapshot)
        .unwrap();
    assert_eq!(pending.completed.attempt_id, verification.attempt_id);
    assert!(recovered.ledger.attempt(&trace.attempt_id).is_none());
    assert_eq!(std::fs::read(path).unwrap(), before);
    assert_eq!(std::fs::read(typed_path).unwrap(), typed_before);
    assert!(load_phase_attempt_ledger_v2(target.path())
        .unwrap()
        .attempts
        .contains_key(&RunAttemptId::parse(&trace.attempt_id).unwrap()));
}

#[test]
fn historical_trace_cannot_be_selected_through_either_writer() {
    let target = tempfile::tempdir().unwrap();
    let trace = completed_tool(target.path(), "trace-old", "trace:expand");
    save_historical_attempt(target.path(), trace.clone());
    let disposition = PhaseAttemptDispositionRecorded::new(
        trace.attempt_id,
        PhaseAttemptDisposition::Selected {
            acknowledged_partial: false,
        },
    );
    let before = std::fs::read(phase_attempt_v2_ledger_path(target.path())).unwrap();
    assert!(append_phase_attempt_disposition_v2_if_present(target.path(), &disposition).is_err());
    assert!(
        crate::workflow_attempts::append_phase_attempt_disposition(target.path(), disposition)
            .is_err()
    );
    assert_eq!(
        std::fs::read(phase_attempt_v2_ledger_path(target.path())).unwrap(),
        before
    );
}

#[test]
fn unknown_historical_tool_is_not_silently_removed() {
    let target = tempfile::tempdir().unwrap();
    let attempt = completed_tool(target.path(), "unknown-historic", "custom:verify");
    save_historical_attempt(target.path(), attempt.clone());
    let recovered = load_phase_attempt_ledger(target.path()).unwrap();
    assert!(recovered.attempt(&attempt.attempt_id).is_some());
}

#[test]
fn legacy_only_recovery_preserves_verification_and_rejects_trace_selection() {
    let target = tempfile::tempdir().unwrap();
    let verification = completed_tool(target.path(), "legacy-verify", "verify:finding");
    let trace = completed_tool(target.path(), "legacy-trace", "trace:expand");
    save_historical_attempt(target.path(), verification.clone());
    save_historical_attempt(target.path(), trace.clone());
    std::fs::remove_file(phase_attempt_v2_ledger_path(target.path())).unwrap();
    let path = phase_attempt_ledger_path(target.path());
    let before = std::fs::read(&path).unwrap();
    let recovered = load_phase_attempt_ledger(target.path()).unwrap();
    let pending = recovered
        .unresolved_for(
            WorkflowPhase::Prove,
            &PhaseTargetSnapshot::capture(target.path()),
        )
        .unwrap();
    assert_eq!(pending.completed.attempt_id, verification.attempt_id);
    assert!(recovered.attempt(&trace.attempt_id).is_none());
    let disposition = PhaseAttemptDispositionRecorded::new(
        trace.attempt_id,
        PhaseAttemptDisposition::Selected {
            acknowledged_partial: false,
        },
    );
    assert!(
        crate::workflow_attempts::append_phase_attempt_disposition(target.path(), disposition)
            .is_err()
    );
    assert_eq!(std::fs::read(path).unwrap(), before);
    assert!(!phase_attempt_v2_ledger_path(target.path()).exists());
}
