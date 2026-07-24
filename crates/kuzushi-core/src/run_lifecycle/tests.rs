use super::*;
use crate::runtime::{RuntimeCost, RuntimeCostReport};
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

fn run_id() -> RunId {
    RunId::parse("run-lifecycle-test").unwrap()
}

fn envelope(
    seq: u64,
    item_id: RunItemId,
    item: RunItemV1,
    previous: Option<&RunItemEnvelopeV1>,
) -> RunItemEnvelopeV1 {
    RunItemEnvelopeV1::new(
        seq,
        run_id(),
        item_id,
        RunItemSource::Dispatch,
        item,
        previous.map(|item| item.event_hash.clone()),
    )
    .unwrap()
}

fn artifact_reference(producing_item_id: RunItemId) -> ArtifactReference {
    artifact_reference_at(producing_item_id, "result.json", 'a')
}

fn artifact_reference_at(
    producing_item_id: RunItemId,
    path: &str,
    digest_character: char,
) -> ArtifactReference {
    ArtifactReference {
        path: SafeText::operator_visible(path),
        kind: SafeText::operator_visible("json"),
        label: SafeText::operator_visible("result"),
        digest: SafeText::operator_visible(format!(
            "sha256:{}",
            digest_character.to_string().repeat(64)
        )),
        byte_count: 2,
        line_count: Some(1),
        producing_item_id,
    }
}

fn requested_tool_call(
    seq: u64,
    item_id: RunItemId,
    call_id: RunCallId,
    previous: Option<&RunItemEnvelopeV1>,
    parent_item_id: Option<RunItemId>,
) -> RunItemEnvelopeV1 {
    let item = envelope(
        seq,
        item_id,
        RunItemV1::ToolCallRequested {
            tool_name: SafeText::operator_visible("security:scan"),
            operation_fingerprint: OperationFingerprint::from_bytes(b"prepared-input"),
            safe_option_names: Vec::new(),
        },
        previous,
    )
    .with_call(call_id)
    .unwrap();
    match parent_item_id {
        Some(parent) => item.with_parent(parent).unwrap(),
        None => item,
    }
}

fn started_tool_call(
    seq: u64,
    item_id: RunItemId,
    call_id: RunCallId,
    previous: &RunItemEnvelopeV1,
    parent_item_id: Option<RunItemId>,
) -> RunItemEnvelopeV1 {
    let item = envelope(
        seq,
        item_id,
        RunItemV1::ToolCallStarted {
            tool_name: SafeText::operator_visible("security:scan"),
            runtime: Some(SafeText::operator_visible("native")),
            model: None,
        },
        Some(previous),
    )
    .with_call(call_id)
    .unwrap();
    match parent_item_id {
        Some(parent) => item.with_parent(parent).unwrap(),
        None => item,
    }
}

fn finished_tool_call(
    seq: u64,
    item_id: RunItemId,
    call_id: RunCallId,
    artifact: ArtifactReference,
    previous: &RunItemEnvelopeV1,
    parent_item_id: Option<RunItemId>,
) -> RunItemEnvelopeV1 {
    let item = envelope(
        seq,
        item_id,
        RunItemV1::ToolCallFinished {
            status: RunItemStatus::Completed,
            cost: RuntimeCostReport::UNAVAILABLE,
            result_artifact: Some(artifact),
            preview: Vec::new(),
            warning_count: 0,
            error_count: 0,
        },
        Some(previous),
    )
    .with_call(call_id)
    .unwrap();
    match parent_item_id {
        Some(parent) => item.with_parent(parent).unwrap(),
        None => item,
    }
}

fn wait_for_committed_seq(committed: &Arc<Mutex<Vec<RunItemEnvelopeV1>>>, expected_seq: u64) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while committed
        .lock()
        .unwrap()
        .last()
        .is_none_or(|item| item.seq < expected_seq)
    {
        assert!(Instant::now() < deadline, "live delivery did not catch up");
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn envelope_hash_chain_and_cost_states_round_trip() {
    let exact = RuntimeCostReport::known(RuntimeCost::from_usd(0.25, "test").unwrap());
    let first = envelope(
        1,
        RunItemId::new(),
        RunItemV1::DiagnosticNotice {
            level: DiagnosticLevel::Info,
            message: SafeText::operator_visible("ready"),
        },
        None,
    );
    let second = envelope(
        2,
        RunItemId::new(),
        RunItemV1::TerminalOutcome {
            status: RunItemStatus::Completed,
            summary: SafeText::operator_visible("complete"),
            cost: exact,
            continuation: WorkflowContinuation::NoFurtherAction {
                reason: SafeText::operator_visible("done"),
            },
        },
        Some(&first),
    );

    second.verify_hash().unwrap();
    let restored: RunItemEnvelopeV1 =
        serde_json::from_slice(&serde_json::to_vec(&second).unwrap()).unwrap();
    assert_eq!(restored, second);
}

#[test]
fn rust_safe_text_policy_redacts_secrets_and_rejects_unsafe_persisted_text() {
    let safe = SafeText::operator_visible("Authorization: Bearer sk-run-item-sentinel");

    assert!(!safe.as_str().contains("sk-run-item-sentinel"));
    assert!(safe.as_str().contains("[REDACTED]"));
    assert!(serde_json::from_str::<SafeText>("\"Authorization: Bearer raw-secret\"").is_err());
    assert!(serde_json::from_value::<SafeText>(serde_json::json!("unsafe\u{7}control")).is_err());
}

#[test]
fn tagged_run_item_variants_reject_unknown_fields() {
    let error = serde_json::from_value::<RunItemV1>(serde_json::json!({
        "type": "diagnostic_notice",
        "level": "info",
        "message": "ready",
        "unexpected": true
    }))
    .unwrap_err();

    assert!(error.to_string().contains("unknown field"), "{error}");
}

#[test]
fn nested_tagged_variants_reject_unknown_fields() {
    let continuation_error = serde_json::from_value::<WorkflowContinuation>(serde_json::json!({
        "kind": "retry",
        "reason": "Retry",
        "unexpected": true
    }))
    .unwrap_err();
    let selected_error = serde_json::from_value::<OperatorDecisionValue>(serde_json::json!({
        "kind": "selected",
        "choice_id": "continue",
        "unexpected": true
    }))
    .unwrap_err();

    assert!(
        continuation_error.to_string().contains("unknown field"),
        "{continuation_error}"
    );
    assert!(
        selected_error.to_string().contains("unknown field"),
        "{selected_error}"
    );
    for kind in ["provided_freeform", "approved", "denied", "deferred"] {
        let error = serde_json::from_value::<OperatorDecisionValue>(serde_json::json!({
            "kind": kind,
            "unexpected": true
        }))
        .unwrap_err();
        assert!(error.to_string().contains("unknown field"), "{error}");
    }
}

#[test]
fn tagged_unit_decision_without_unknown_fields_still_round_trips() {
    let decision = serde_json::from_value::<OperatorDecisionValue>(serde_json::json!({
        "kind": "approved"
    }))
    .unwrap();

    assert_eq!(decision, OperatorDecisionValue::Approved);
    assert_eq!(
        serde_json::to_value(decision).unwrap(),
        serde_json::json!({"kind": "approved"})
    );
}

#[test]
fn application_owned_plan_extension_preserves_all_prior_task_order() {
    let target = tempfile::tempdir().unwrap();
    let run_id = "plan-extension-order-test";
    let root = RunObservationHandle::jsonl(target.path(), run_id).unwrap();
    let plan = root
        .start_plan("Scan the accepted scope", ["accepted scan".to_string()])
        .unwrap();
    let scoped = plan.tasks()[0].observation();

    let mut first_extension = scoped.plan_handle().unwrap().unwrap();
    first_extension
        .extend_tasks(["dep-hygiene".to_string(), "secret-scan".to_string()])
        .unwrap();
    let mut second_extension = scoped.plan_handle().unwrap().unwrap();
    second_extension
        .extend_tasks(["semgrep".to_string()])
        .unwrap();

    let projection = load_run_projection(target.path(), run_id)
        .unwrap()
        .projection;
    let plan = projection.plan.unwrap();
    let titles = plan
        .task_ids
        .iter()
        .map(|task_id| projection.tasks[task_id].title.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        titles,
        ["accepted scan", "dep-hygiene", "secret-scan", "semgrep"]
    );
    assert_eq!(projection.task_order, plan.task_ids);
}

#[test]
fn saturation_marker_distinguishes_unique_key_loss_from_coalescing() {
    let progress_item_id = RunItemId::new();
    let truncated = envelope(
        1,
        RunItemId::new(),
        RunItemV1::ProgressTruncated {
            progress_item_id,
            omitted_count: 9,
        },
        None,
    );
    let marker = envelope(
        2,
        RunItemId::new(),
        RunItemV1::DiagnosticNotice {
            level: DiagnosticLevel::Warning,
            message: SafeText::operator_visible(RUN_PROGRESS_SATURATION_MARKER),
        },
        Some(&truncated),
    );

    let projection = reduce_run_items([truncated, marker]);

    assert_eq!(
        projection.lifecycle_health().progress,
        RunProgressFidelity::Saturated {
            omitted_at_least: 9
        }
    );
}

#[test]
fn live_projection_degradation_is_sticky_at_the_last_valid_prefix() {
    let first = envelope(
        1,
        RunItemId::new(),
        RunItemV1::DiagnosticNotice {
            level: DiagnosticLevel::Info,
            message: SafeText::operator_visible("valid prefix"),
        },
        None,
    );
    let gap = envelope(
        3,
        RunItemId::new(),
        RunItemV1::DiagnosticNotice {
            level: DiagnosticLevel::Warning,
            message: SafeText::operator_visible("gap"),
        },
        Some(&first),
    );
    let later = envelope(
        2,
        RunItemId::new(),
        RunItemV1::DiagnosticNotice {
            level: DiagnosticLevel::Info,
            message: SafeText::operator_visible("must not apply"),
        },
        Some(&first),
    );
    let mut projection = RunProjection::default();

    projection.apply_committed(first).unwrap();
    assert!(projection.apply_committed(gap).is_err());
    let degraded = projection.health.clone();
    assert!(projection.apply_committed(later).is_err());

    assert_eq!(projection.last_committed_seq, 1);
    assert_eq!(projection.timeline.len(), 1);
    assert_eq!(projection.health, degraded);
}

#[test]
fn typed_artifact_without_a_known_terminal_call_degrades() {
    let artifact = envelope(
        1,
        RunItemId::new(),
        RunItemV1::ArtifactProduced {
            artifact: artifact_reference(RunItemId::new()),
        },
        None,
    );

    let projection = reduce_run_items([artifact]);

    assert!(matches!(
        projection.health,
        ProjectionHealth::Degraded { ref reason, .. }
            if reason.contains("unknown producing call")
    ));
    assert!(projection.artifacts.is_empty());
}

#[test]
fn artifact_cannot_retroactively_become_a_rejected_calls_result() {
    let item_id = RunItemId::new();
    let call_id = RunCallId::new();
    let requested = envelope(
        1,
        item_id,
        RunItemV1::ToolCallRequested {
            tool_name: SafeText::operator_visible("sast:scan"),
            operation_fingerprint: OperationFingerprint::from_bytes(b"rejected-input"),
            safe_option_names: Vec::new(),
        },
        None,
    )
    .with_call(call_id)
    .unwrap();
    let rejected = envelope(
        2,
        item_id,
        RunItemV1::ToolCallRejected {
            reason_class: SafeText::operator_visible("preparation_policy"),
            detail: SafeText::operator_visible("unknown option"),
        },
        Some(&requested),
    )
    .with_call(call_id)
    .unwrap();
    let result_id = RunItemId::new();
    let result = envelope(
        3,
        result_id,
        RunItemV1::ArtifactProduced {
            artifact: artifact_reference(item_id),
        },
        Some(&rejected),
    )
    .with_call(call_id)
    .unwrap();
    let projection = reduce_run_items([requested, rejected, result]);

    assert!(matches!(
        projection.health,
        ProjectionHealth::Degraded { ref reason, .. }
            if reason.contains("result artifact was not linked by call settlement")
    ));
    let call = &projection.calls[&call_id];
    assert_eq!(call.status, RunItemStatus::Blocked);
    assert!(call.result_artifact.is_none());
    assert!(call.related_artifact_ids.is_empty());
    assert!(!projection.artifacts.contains_key(&result_id));
}

#[test]
fn deferred_pre_start_failure_may_settle_with_its_exact_result_artifact() {
    let item_id = RunItemId::new();
    let call_id = RunCallId::new();
    let requested = envelope(
        1,
        item_id,
        RunItemV1::ToolCallRequested {
            tool_name: SafeText::operator_visible("sast:scan"),
            operation_fingerprint: OperationFingerprint::from_bytes(b"rejected-input"),
            safe_option_names: Vec::new(),
        },
        None,
    )
    .with_call(call_id)
    .unwrap();
    let result = artifact_reference(item_id);
    let finished = envelope(
        2,
        item_id,
        RunItemV1::ToolCallFinished {
            status: RunItemStatus::Failed,
            cost: RuntimeCostReport::UNAVAILABLE,
            result_artifact: Some(result.clone()),
            preview: vec![SafeText::preview_line("rejected before execution")],
            warning_count: 0,
            error_count: 1,
        },
        Some(&requested),
    )
    .with_call(call_id)
    .unwrap();
    let produced_id = RunItemId::new();
    let produced = envelope(
        3,
        produced_id,
        RunItemV1::ArtifactProduced {
            artifact: result.clone(),
        },
        Some(&finished),
    )
    .with_call(call_id)
    .unwrap();

    let projection = reduce_run_items([requested, finished, produced]);

    assert_eq!(projection.health, ProjectionHealth::Healthy);
    assert_eq!(projection.calls[&call_id].status, RunItemStatus::Failed);
    assert_eq!(projection.calls[&call_id].result_artifact, Some(result));
    assert!(projection.artifacts.contains_key(&produced_id));
}

#[test]
fn artifact_call_scope_must_match_the_exact_root_call() {
    let item_id = RunItemId::new();
    let call_id = RunCallId::new();
    let requested = requested_tool_call(1, item_id, call_id, None, None);
    let started = started_tool_call(2, item_id, call_id, &requested, None);
    let result = artifact_reference(item_id);
    let finished = finished_tool_call(3, item_id, call_id, result.clone(), &started, None);
    let produced = envelope(
        4,
        RunItemId::new(),
        RunItemV1::ArtifactProduced { artifact: result },
        Some(&finished),
    )
    .with_call(RunCallId::new())
    .unwrap();

    let projection = reduce_run_items([requested, started, finished, produced]);

    assert!(matches!(
        projection.health,
        ProjectionHealth::Degraded { ref reason, .. }
            if reason.contains("artifact call scope does not match")
    ));
    assert_eq!(projection.last_committed_seq, 3);
    assert!(projection.calls[&call_id].related_artifact_ids.is_empty());
}

#[test]
fn exact_duplicate_scoped_artifact_settlement_is_idempotent() {
    let item_id = RunItemId::new();
    let call_id = RunCallId::new();
    let requested = requested_tool_call(1, item_id, call_id, None, None);
    let started = started_tool_call(2, item_id, call_id, &requested, None);
    let result = artifact_reference(item_id);
    let finished = finished_tool_call(3, item_id, call_id, result.clone(), &started, None);
    let produced_id = RunItemId::new();
    let produced = envelope(
        4,
        produced_id,
        RunItemV1::ArtifactProduced { artifact: result },
        Some(&finished),
    )
    .with_call(call_id)
    .unwrap();

    let projection = reduce_run_items([requested, started, finished, produced.clone(), produced]);

    assert_eq!(projection.health, ProjectionHealth::Healthy);
    assert_eq!(projection.artifacts.len(), 1);
    assert_eq!(
        projection.calls[&call_id].related_artifact_ids,
        vec![produced_id]
    );
}

#[test]
fn canonical_result_path_cannot_move_between_root_calls() {
    let first_item_id = RunItemId::new();
    let first_call_id = RunCallId::new();
    let first_requested = requested_tool_call(1, first_item_id, first_call_id, None, None);
    let first_started = started_tool_call(2, first_item_id, first_call_id, &first_requested, None);
    let first_finished = finished_tool_call(
        3,
        first_item_id,
        first_call_id,
        artifact_reference_at(first_item_id, "result.json", 'a'),
        &first_started,
        None,
    );
    let second_item_id = RunItemId::new();
    let second_call_id = RunCallId::new();
    let second_requested = requested_tool_call(
        4,
        second_item_id,
        second_call_id,
        Some(&first_finished),
        None,
    );
    let second_started =
        started_tool_call(5, second_item_id, second_call_id, &second_requested, None);
    let second_finished = finished_tool_call(
        6,
        second_item_id,
        second_call_id,
        artifact_reference_at(second_item_id, "result.json", 'b'),
        &second_started,
        None,
    );

    let projection = reduce_run_items([
        first_requested,
        first_started,
        first_finished,
        second_requested,
        second_started,
        second_finished,
    ]);

    assert!(matches!(
        projection.health,
        ProjectionHealth::Degraded { ref reason, .. }
            if reason.contains("canonical result path or digest")
    ));
    assert_eq!(
        projection.calls[&first_call_id].status,
        RunItemStatus::Completed
    );
    assert_eq!(
        projection.calls[&second_call_id].status,
        RunItemStatus::Running
    );
}

#[test]
fn canonical_result_digest_cannot_cross_link_nested_calls() {
    let parent_item_id = RunItemId::new();
    let parent_call_id = RunCallId::new();
    let parent_requested = requested_tool_call(1, parent_item_id, parent_call_id, None, None);
    let parent_started =
        started_tool_call(2, parent_item_id, parent_call_id, &parent_requested, None);
    let first_item_id = RunItemId::new();
    let first_call_id = RunCallId::new();
    let first_requested = requested_tool_call(
        3,
        first_item_id,
        first_call_id,
        Some(&parent_started),
        Some(parent_item_id),
    );
    let first_started = started_tool_call(
        4,
        first_item_id,
        first_call_id,
        &first_requested,
        Some(parent_item_id),
    );
    let first_result = artifact_reference_at(first_item_id, "nested-a.json", 'a');
    let first_finished = finished_tool_call(
        5,
        first_item_id,
        first_call_id,
        first_result.clone(),
        &first_started,
        Some(parent_item_id),
    );
    let produced_id = RunItemId::new();
    let first_produced = envelope(
        6,
        produced_id,
        RunItemV1::ArtifactProduced {
            artifact: first_result,
        },
        Some(&first_finished),
    )
    .with_call(first_call_id)
    .unwrap();
    let second_item_id = RunItemId::new();
    let second_call_id = RunCallId::new();
    let second_requested = requested_tool_call(
        7,
        second_item_id,
        second_call_id,
        Some(&first_produced),
        Some(parent_item_id),
    );
    let second_started = started_tool_call(
        8,
        second_item_id,
        second_call_id,
        &second_requested,
        Some(parent_item_id),
    );
    let second_finished = finished_tool_call(
        9,
        second_item_id,
        second_call_id,
        artifact_reference_at(second_item_id, "nested-b.json", 'a'),
        &second_started,
        Some(parent_item_id),
    );

    let projection = reduce_run_items([
        parent_requested,
        parent_started,
        first_requested,
        first_started,
        first_finished,
        first_produced,
        second_requested,
        second_started,
        second_finished,
    ]);

    assert!(matches!(
        projection.health,
        ProjectionHealth::Degraded { ref reason, .. }
            if reason.contains("canonical result path or digest")
    ));
    assert_eq!(
        projection.calls[&first_call_id].related_artifact_ids,
        vec![produced_id]
    );
    assert_eq!(
        projection.calls[&second_call_id].status,
        RunItemStatus::Running
    );
}

#[test]
fn reducer_preserves_call_identity_and_terminal_continuation() {
    let item_id = RunItemId::new();
    let call_id = RunCallId::new();
    let requested = envelope(
        1,
        item_id,
        RunItemV1::ToolCallRequested {
            tool_name: SafeText::operator_visible("sast:scan"),
            operation_fingerprint: OperationFingerprint::from_bytes(b"prepared-input"),
            safe_option_names: vec![SafeText::operator_visible("engine")],
        },
        None,
    )
    .with_call(call_id)
    .unwrap();
    let started = envelope(
        2,
        item_id,
        RunItemV1::ToolCallStarted {
            tool_name: SafeText::operator_visible("sast:scan"),
            runtime: Some(SafeText::operator_visible("native")),
            model: None,
        },
        Some(&requested),
    )
    .with_call(call_id)
    .unwrap();
    let finished = envelope(
        3,
        item_id,
        RunItemV1::ToolCallFinished {
            status: RunItemStatus::Partial,
            cost: RuntimeCostReport::INCOMPLETE_ZERO,
            result_artifact: None,
            preview: vec![SafeText::operator_visible("no analyzable evidence")],
            warning_count: 1,
            error_count: 0,
        },
        Some(&started),
    )
    .with_call(call_id)
    .unwrap();
    let terminal = envelope(
        4,
        RunItemId::new(),
        RunItemV1::TerminalOutcome {
            status: RunItemStatus::Partial,
            summary: SafeText::operator_visible("partial scan"),
            cost: RuntimeCostReport::INCOMPLETE_ZERO,
            continuation: WorkflowContinuation::InspectRun {
                run_id: run_id(),
                reason: SafeText::operator_visible("inspect partial evidence"),
            },
        },
        Some(&finished),
    );

    let projection = reduce_run_items([requested, started, finished, terminal]);

    assert_eq!(projection.health, ProjectionHealth::Healthy);
    assert_eq!(projection.calls[&call_id].status, RunItemStatus::Partial);
    assert!(matches!(
        projection.continuation,
        Some(WorkflowContinuation::InspectRun { .. })
    ));
}

#[test]
fn reducer_degrades_when_terminal_outcome_precedes_call_settlement() {
    let item_id = RunItemId::new();
    let call_id = RunCallId::new();
    let requested = envelope(
        1,
        item_id,
        RunItemV1::ToolCallRequested {
            tool_name: SafeText::operator_visible("sast:scan"),
            operation_fingerprint: OperationFingerprint::from_bytes(b"prepared-input"),
            safe_option_names: Vec::new(),
        },
        None,
    )
    .with_call(call_id)
    .unwrap();
    let started = envelope(
        2,
        item_id,
        RunItemV1::ToolCallStarted {
            tool_name: SafeText::operator_visible("sast:scan"),
            runtime: Some(SafeText::operator_visible("native")),
            model: None,
        },
        Some(&requested),
    )
    .with_call(call_id)
    .unwrap();
    let terminal = envelope(
        3,
        RunItemId::new(),
        RunItemV1::TerminalOutcome {
            status: RunItemStatus::Completed,
            summary: SafeText::operator_visible("complete"),
            cost: RuntimeCostReport::UNAVAILABLE,
            continuation: WorkflowContinuation::NoFurtherAction {
                reason: SafeText::operator_visible("done"),
            },
        },
        Some(&started),
    );

    let projection = reduce_run_items([requested, started, terminal]);

    assert!(matches!(
        projection.health,
        ProjectionHealth::Degraded { .. }
    ));
    assert_eq!(projection.last_committed_seq, 2);
    assert!(projection.terminal.is_none());
}

#[test]
fn reducer_accepts_model_start_as_the_first_model_call_item() {
    let item_id = RunItemId::new();
    let call_id = RunCallId::new();
    let started = envelope(
        1,
        item_id,
        RunItemV1::ModelCallStarted {
            provider: SafeText::operator_visible("anthropic"),
            model: SafeText::operator_visible("claude-test"),
            operation_fingerprint: OperationFingerprint::from_bytes(b"model-request"),
        },
        None,
    )
    .with_call(call_id)
    .unwrap();
    let finished = envelope(
        2,
        item_id,
        RunItemV1::ModelCallFinished {
            provider: SafeText::operator_visible("anthropic"),
            model: SafeText::operator_visible("claude-test"),
            status: RunItemStatus::Completed,
            latency_ms: 10,
            usage: ModelUsage {
                input_tokens: Some(1),
                output_tokens: Some(1),
            },
            cost: RuntimeCostReport::INCOMPLETE_ZERO,
            error_class: None,
        },
        Some(&started),
    )
    .with_call(call_id)
    .unwrap();

    let projection = reduce_run_items([started, finished]);

    assert_eq!(projection.health, ProjectionHealth::Healthy);
    assert_eq!(projection.calls[&call_id].kind, CallKind::Model);
    assert_eq!(projection.calls[&call_id].status, RunItemStatus::Completed);
}

#[test]
fn reducer_keeps_mixed_outer_tool_and_model_call_sequence_healthy() {
    let plan_item_id = RunItemId::new();
    let task_item_id = RunItemId::new();
    let task_id = RunTaskId::new();
    let tool_item_id = RunItemId::new();
    let tool_call_id = RunCallId::new();
    let model_item_id = RunItemId::new();
    let model_call_id = RunCallId::new();
    let plan = envelope(
        1,
        plan_item_id,
        RunItemV1::PlanUpdated {
            revision: 1,
            title: SafeText::operator_visible("verify finding"),
            status: RunItemStatus::Pending,
            task_ids: vec![task_id],
        },
        None,
    );
    let task_pending = envelope(
        2,
        task_item_id,
        RunItemV1::TaskUpdated {
            title: SafeText::operator_visible("verification:verify"),
            status: RunItemStatus::Pending,
            detail: None,
        },
        Some(&plan),
    )
    .with_task(task_id)
    .unwrap();
    let requested = envelope(
        3,
        tool_item_id,
        RunItemV1::ToolCallRequested {
            tool_name: SafeText::operator_visible("verification:verify"),
            operation_fingerprint: OperationFingerprint::from_bytes(b"prepared-verification"),
            safe_option_names: vec![SafeText::operator_visible("findingId")],
        },
        Some(&task_pending),
    )
    .with_call(tool_call_id)
    .unwrap();
    let task_running = envelope(
        4,
        task_item_id,
        RunItemV1::TaskUpdated {
            title: SafeText::operator_visible("verification:verify"),
            status: RunItemStatus::Running,
            detail: None,
        },
        Some(&requested),
    )
    .with_task(task_id)
    .unwrap();
    let tool_started = envelope(
        5,
        tool_item_id,
        RunItemV1::ToolCallStarted {
            tool_name: SafeText::operator_visible("verification:verify"),
            runtime: Some(SafeText::operator_visible("agent")),
            model: Some(SafeText::operator_visible("claude-test")),
        },
        Some(&task_running),
    )
    .with_call(tool_call_id)
    .unwrap();
    let model_started = envelope(
        6,
        model_item_id,
        RunItemV1::ModelCallStarted {
            provider: SafeText::operator_visible("anthropic"),
            model: SafeText::operator_visible("claude-test"),
            operation_fingerprint: OperationFingerprint::from_bytes(b"verification-model-call"),
        },
        Some(&tool_started),
    )
    .with_call(model_call_id)
    .unwrap();
    let model_finished = envelope(
        7,
        model_item_id,
        RunItemV1::ModelCallFinished {
            provider: SafeText::operator_visible("anthropic"),
            model: SafeText::operator_visible("claude-test"),
            status: RunItemStatus::Completed,
            latency_ms: 10,
            usage: ModelUsage {
                input_tokens: Some(10),
                output_tokens: Some(5),
            },
            cost: RuntimeCostReport::INCOMPLETE_ZERO,
            error_class: None,
        },
        Some(&model_started),
    )
    .with_call(model_call_id)
    .unwrap();
    let tool_finished = envelope(
        8,
        tool_item_id,
        RunItemV1::ToolCallFinished {
            status: RunItemStatus::Completed,
            cost: RuntimeCostReport::INCOMPLETE_ZERO,
            result_artifact: None,
            preview: vec![SafeText::operator_visible("verification complete")],
            warning_count: 0,
            error_count: 0,
        },
        Some(&model_finished),
    )
    .with_call(tool_call_id)
    .unwrap();
    let task_finished = envelope(
        9,
        task_item_id,
        RunItemV1::TaskUpdated {
            title: SafeText::operator_visible("verification:verify"),
            status: RunItemStatus::Completed,
            detail: None,
        },
        Some(&tool_finished),
    )
    .with_task(task_id)
    .unwrap();
    let terminal = envelope(
        10,
        RunItemId::new(),
        RunItemV1::TerminalOutcome {
            status: RunItemStatus::Completed,
            summary: SafeText::operator_visible("verification complete"),
            cost: RuntimeCostReport::INCOMPLETE_ZERO,
            continuation: WorkflowContinuation::NoFurtherAction {
                reason: SafeText::operator_visible("proof persisted"),
            },
        },
        Some(&task_finished),
    );

    let projection = reduce_run_items([
        plan,
        task_pending,
        requested,
        task_running,
        tool_started,
        model_started,
        model_finished,
        tool_finished,
        task_finished,
        terminal,
    ]);

    assert_eq!(projection.health, ProjectionHealth::Healthy);
    assert_eq!(projection.last_committed_seq, 10);
    assert_eq!(
        projection.calls[&tool_call_id].status,
        RunItemStatus::Completed
    );
    assert_eq!(
        projection.calls[&model_call_id].status,
        RunItemStatus::Completed
    );
    assert_eq!(
        projection.terminal.as_ref().map(|terminal| terminal.status),
        Some(RunItemStatus::Completed)
    );
}

#[test]
fn reducer_degrades_at_gaps_hash_breaks_or_orphan_completions() {
    let orphan = envelope(
        1,
        RunItemId::new(),
        RunItemV1::ToolCallFinished {
            status: RunItemStatus::Completed,
            cost: RuntimeCostReport::UNAVAILABLE,
            result_artifact: None,
            preview: Vec::new(),
            warning_count: 0,
            error_count: 0,
        },
        None,
    )
    .with_call(RunCallId::new())
    .unwrap();
    let projection = reduce_run_items([orphan]);
    assert!(matches!(
        projection.health,
        ProjectionHealth::Degraded { .. }
    ));

    let gap = envelope(
        2,
        RunItemId::new(),
        RunItemV1::DiagnosticNotice {
            level: DiagnosticLevel::Warning,
            message: SafeText::operator_visible("gap"),
        },
        None,
    );
    assert!(matches!(
        reduce_run_items([gap]).health,
        ProjectionHealth::Degraded { .. }
    ));
}

#[test]
fn reducer_accepts_identical_duplicates_and_rejects_divergent_ones() {
    let first = envelope(
        1,
        RunItemId::new(),
        RunItemV1::DiagnosticNotice {
            level: DiagnosticLevel::Info,
            message: SafeText::operator_visible("one"),
        },
        None,
    );
    let duplicate = first.clone();
    let healthy = reduce_run_items([first.clone(), duplicate]);
    assert_eq!(healthy.health, ProjectionHealth::Healthy);
    assert_eq!(healthy.timeline.len(), 1);

    let mut divergent = first.clone();
    divergent.event_hash = format!("sha256:{}", "0".repeat(64));
    let degraded = reduce_run_items([first, divergent]);
    assert!(matches!(degraded.health, ProjectionHealth::Degraded { .. }));
}

#[test]
fn writer_publishes_only_durable_items_and_restarts_from_tail() {
    let target = tempfile::tempdir().unwrap();
    let run_id = crate::run_artifacts::new_run_id("typed");
    let committed = Arc::new(Mutex::new(Vec::new()));
    let subscriber_items = Arc::clone(&committed);
    let subscriber: CommittedItemSubscriber = Arc::new(move |item| {
        subscriber_items.lock().unwrap().push(item.clone());
    });
    let writer = RunItemWriter::open(target.path(), &run_id, Some(subscriber)).unwrap();
    let notice = RunItemRecord::new(
        RunItemId::new(),
        RunItemSource::Persistence,
        RunItemV1::DiagnosticNotice {
            level: DiagnosticLevel::Info,
            message: SafeText::operator_visible("persisted"),
        },
    );
    writer.emit(notice).unwrap();
    let terminal = writer
        .emit_and_flush(RunItemRecord::new(
            RunItemId::new(),
            RunItemSource::Workflow,
            RunItemV1::TerminalOutcome {
                status: RunItemStatus::Completed,
                summary: SafeText::operator_visible("complete"),
                cost: RuntimeCostReport::UNAVAILABLE,
                continuation: WorkflowContinuation::NoFurtherAction {
                    reason: SafeText::operator_visible("done"),
                },
            },
        ))
        .unwrap();
    writer.shutdown().unwrap();

    let read = read_run_items(target.path(), &run_id).unwrap().unwrap();
    assert_eq!(read.health, ProjectionHealth::Healthy);
    assert_eq!(read.items.last().unwrap().event_hash, terminal.event_hash);
    assert_eq!(committed.lock().unwrap().as_slice(), read.items.as_slice());

    let restarted = RunItemWriter::open(target.path(), &run_id, None).unwrap();
    let next = restarted
        .emit_and_flush(RunItemRecord::new(
            RunItemId::new(),
            RunItemSource::Persistence,
            RunItemV1::DiagnosticNotice {
                level: DiagnosticLevel::Info,
                message: SafeText::operator_visible("restart"),
            },
        ))
        .unwrap();
    restarted.shutdown().unwrap();
    assert_eq!(next.seq, terminal.seq + 1);
}

#[test]
fn preparation_rejection_preserves_identity_without_raw_option_values() {
    let target = tempfile::tempdir().unwrap();
    let run_id = crate::run_artifacts::new_run_id("rejected");
    let observation = RunObservationHandle::jsonl(target.path(), &run_id).unwrap();
    let scoped = emit_preparation_rejection(
        &observation,
        "patch:reverify",
        &serde_json::json!({"applicationId": "raw-option-sentinel"}),
        "option_policy",
        "required option was rejected",
    )
    .unwrap();
    scoped.flush().unwrap();

    let read = load_run_projection(target.path(), &run_id).unwrap();
    assert_eq!(read.projection.health, ProjectionHealth::Healthy);
    assert_eq!(read.projection.tasks.len(), 1);
    assert_eq!(read.projection.calls.len(), 1);
    assert_eq!(
        read.projection
            .terminal
            .as_ref()
            .map(|terminal| terminal.status),
        Some(RunItemStatus::Blocked)
    );
    assert_eq!(
        read.projection.plan.as_ref().map(|plan| plan.status),
        Some(RunItemStatus::Blocked)
    );
    assert_eq!(
        read.projection
            .calls
            .values()
            .next()
            .map(|call| call.status),
        Some(RunItemStatus::Blocked)
    );
    let stream = std::fs::read_to_string(crate::run_artifacts::run_artifact_path(
        target.path(),
        &run_id,
        "items.jsonl",
    ))
    .unwrap();
    assert!(!stream.contains("raw-option-sentinel"));
}

#[test]
fn every_live_prefix_matches_the_durable_projection() {
    let target = tempfile::tempdir().unwrap();
    let run_id = crate::run_artifacts::new_run_id("prefix");
    let committed = Arc::new(Mutex::new(Vec::new()));
    let subscriber_items = Arc::clone(&committed);
    let subscriber: CommittedItemSubscriber = Arc::new(move |item| {
        subscriber_items.lock().unwrap().push(item.clone());
    });
    let writer = RunItemWriter::open(target.path(), &run_id, Some(subscriber)).unwrap();
    let task_id = RunTaskId::new();
    let task_item_id = RunItemId::new();
    let records = [
        RunItemRecord::new(
            task_item_id,
            RunItemSource::Workflow,
            RunItemV1::TaskUpdated {
                title: SafeText::operator_visible("semantic task"),
                status: RunItemStatus::Pending,
                detail: None,
            },
        )
        .with_task(task_id),
        RunItemRecord::new(
            task_item_id,
            RunItemSource::Workflow,
            RunItemV1::TaskUpdated {
                title: SafeText::operator_visible("semantic task"),
                status: RunItemStatus::Running,
                detail: None,
            },
        )
        .with_task(task_id),
        RunItemRecord::new(
            task_item_id,
            RunItemSource::Workflow,
            RunItemV1::TaskUpdated {
                title: SafeText::operator_visible("semantic task"),
                status: RunItemStatus::Completed,
                detail: Some(SafeText::operator_visible("source-backed result")),
            },
        )
        .with_task(task_id),
    ];

    for record in records {
        let committed_item = writer.emit_and_flush(record).unwrap();
        wait_for_committed_seq(&committed, committed_item.seq);
        let live = reduce_run_items(committed.lock().unwrap().clone());
        let disk = load_run_projection(target.path(), &run_id)
            .unwrap()
            .projection;
        assert_eq!(live, disk);
    }
    writer.shutdown().unwrap();
}

#[test]
fn slow_item_subscriber_does_not_hide_durable_high_watermark_or_block_writer() {
    let target = tempfile::tempdir().unwrap();
    let run_id = crate::run_artifacts::new_run_id("slow-delivery");
    let delivered = Arc::new(Mutex::new(Vec::new()));
    let first_delivery = Arc::new(AtomicBool::new(true));
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let (started_sender, started_receiver) = mpsc::sync_channel(1);
    let item_subscriber: CommittedItemSubscriber = {
        let delivered = Arc::clone(&delivered);
        let first_delivery = Arc::clone(&first_delivery);
        let release = Arc::clone(&release);
        Arc::new(move |item| {
            if first_delivery.swap(false, Ordering::AcqRel) {
                started_sender.send(()).unwrap();
                let (released, wake) = &*release;
                let released = released.lock().unwrap();
                let _ = wake
                    .wait_timeout_while(released, Duration::from_secs(5), |value| !*value)
                    .unwrap();
            }
            delivered.lock().unwrap().push(item.clone());
        })
    };
    let (range_sender, range_receiver) = mpsc::channel();
    let range_subscriber: CommittedRangeSubscriber =
        Arc::new(move |range| range_sender.send(range).unwrap());
    let writer = RunItemWriter::open_with_subscribers(
        target.path(),
        &run_id,
        Some(item_subscriber),
        Some(range_subscriber),
    )
    .unwrap();

    let first = writer
        .emit_and_flush(diagnostic_notice("first durable item"))
        .unwrap();
    started_receiver
        .recv_timeout(Duration::from_secs(2))
        .unwrap();
    let (reply_sender, reply_receiver) = mpsc::sync_channel(1);
    let cloned_writer = writer.clone();
    let writer_thread = std::thread::spawn(move || {
        reply_sender.send(cloned_writer.emit_and_flush(diagnostic_notice("second durable item")))
    });
    let second = reply_receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("durable writer must not wait for the item subscriber")
        .unwrap();
    assert_eq!(second.seq, first.seq + 1);
    wait_for_durable_range(&range_receiver, second.seq);
    assert!(delivered.lock().unwrap().is_empty());

    let (released, wake) = &*release;
    *released.lock().unwrap() = true;
    wake.notify_all();
    writer_thread.join().unwrap().unwrap();
    writer.shutdown().unwrap();

    let delivered = delivered.lock().unwrap().clone();
    let replay = load_run_projection(target.path(), &run_id)
        .unwrap()
        .projection;
    assert_eq!(reduce_run_items(delivered), replay);
    assert_eq!(replay.last_committed_seq, second.seq);
    assert_eq!(replay.health, ProjectionHealth::Healthy);
}

fn diagnostic_notice(message: &str) -> RunItemRecord {
    RunItemRecord::new(
        RunItemId::new(),
        RunItemSource::Persistence,
        RunItemV1::DiagnosticNotice {
            level: DiagnosticLevel::Info,
            message: SafeText::operator_visible(message),
        },
    )
}

fn wait_for_durable_range(receiver: &mpsc::Receiver<CommittedRange>, expected_seq: u64) {
    let mut durable_seq = 0;
    while durable_seq < expected_seq {
        let range = receiver.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(range.first_seq > 0);
        assert!(range.first_seq <= range.through_seq);
        durable_seq = durable_seq.max(range.through_seq);
    }
}

#[test]
fn coalescing_discloses_all_omitted_progress_before_terminal_delivery() {
    const UPDATE_COUNT: u64 = 10_000;
    let target = tempfile::tempdir().unwrap();
    let run_id = crate::run_artifacts::new_run_id("pressure");
    let writer = RunItemWriter::open(target.path(), &run_id, None).unwrap();
    let progress_item_id = RunItemId::new();
    for completed in 0..UPDATE_COUNT {
        writer
            .emit_coalescible(RunItemRecord::new(
                progress_item_id,
                RunItemSource::Runtime,
                RunItemV1::SafeReasoningSummary {
                    text: SafeText::operator_visible(format!("safe update {completed}")),
                    redaction_policy_version: RUN_ITEM_REDACTION_POLICY_VERSION,
                },
            ))
            .unwrap();
    }
    writer
        .emit_and_flush(RunItemRecord::new(
            RunItemId::new(),
            RunItemSource::Workflow,
            RunItemV1::TerminalOutcome {
                status: RunItemStatus::Completed,
                summary: SafeText::operator_visible("complete"),
                cost: RuntimeCostReport::UNAVAILABLE,
                continuation: WorkflowContinuation::NoFurtherAction {
                    reason: SafeText::operator_visible("done"),
                },
            },
        ))
        .unwrap();
    writer.shutdown().unwrap();

    let read = read_run_items(target.path(), &run_id).unwrap().unwrap();
    let persisted_updates = read
        .items
        .iter()
        .filter(|item| matches!(item.item, RunItemV1::SafeReasoningSummary { .. }))
        .count() as u64;
    let omitted = read
        .items
        .iter()
        .filter_map(|item| match item.item {
            RunItemV1::ProgressTruncated { omitted_count, .. } => Some(omitted_count),
            _ => None,
        })
        .sum::<u64>();
    assert_eq!(persisted_updates + omitted, UPDATE_COUNT);
    assert!(read.items.len() < 2_048);
    assert!(matches!(
        read.items.last().map(|item| &item.item),
        Some(RunItemV1::TerminalOutcome { .. })
    ));
}

#[test]
fn exact_progress_requires_a_truthful_completed_total_pair() {
    let progress = |completed, total| RunItemV1::ToolCallProgress {
        message: SafeText::operator_visible("Indexing repository files"),
        completed,
        total,
    };

    assert!(RunItemPersistencePolicy::validate(&progress(None, None)).is_ok());
    assert!(RunItemPersistencePolicy::validate(&progress(Some(421), Some(832))).is_ok());
    assert!(RunItemPersistencePolicy::validate(&progress(Some(421), None)).is_err());
    assert!(RunItemPersistencePolicy::validate(&progress(Some(0), Some(0))).is_err());
    assert!(RunItemPersistencePolicy::validate(&progress(Some(833), Some(832))).is_err());
}

#[test]
fn reader_stops_at_the_last_valid_prefix_for_corruption_and_truncation() {
    let target = tempfile::tempdir().unwrap();
    let run_id = crate::run_artifacts::new_run_id("corrupt");
    let writer = RunItemWriter::open(target.path(), &run_id, None).unwrap();
    writer
        .emit_and_flush(RunItemRecord::new(
            RunItemId::new(),
            RunItemSource::Persistence,
            RunItemV1::DiagnosticNotice {
                level: DiagnosticLevel::Info,
                message: SafeText::operator_visible("valid prefix"),
            },
        ))
        .unwrap();
    writer.shutdown().unwrap();
    let path = crate::run_artifacts::run_dir(target.path(), &run_id).join("items.jsonl");
    OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(br#"{"schemaVersion":1,"truncated":"#)
        .unwrap();

    let read = read_run_items(target.path(), &run_id).unwrap().unwrap();
    assert_eq!(read.items.len(), 1);
    assert!(matches!(
        read.health,
        ProjectionHealth::Degraded {
            valid_through_seq: 1,
            ..
        }
    ));
    let projection = load_run_projection(target.path(), &run_id)
        .unwrap()
        .projection;
    assert_eq!(projection.last_committed_seq, 1);
    assert!(matches!(
        projection.health,
        ProjectionHealth::Degraded { .. }
    ));
}

#[test]
fn reader_rejects_unknown_nested_fields_before_hash_verification() {
    let target = tempfile::tempdir().unwrap();
    let item = envelope(
        1,
        RunItemId::new(),
        RunItemV1::TerminalOutcome {
            status: RunItemStatus::Failed,
            summary: SafeText::operator_visible("failed"),
            cost: RuntimeCostReport::UNAVAILABLE,
            continuation: WorkflowContinuation::Retry {
                reason: SafeText::operator_visible("Retry"),
            },
        },
        None,
    );
    let mut persisted = serde_json::to_value(&item).unwrap();
    persisted["item"]["continuation"]["unexpected"] = serde_json::json!(true);
    let path =
        crate::run_artifacts::run_dir(target.path(), item.run_id.as_str()).join("items.jsonl");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(
        path,
        format!("{}\n", serde_json::to_string(&persisted).unwrap()),
    )
    .unwrap();

    let read = read_run_items(target.path(), item.run_id.as_str())
        .unwrap()
        .unwrap();

    assert!(read.items.is_empty());
    let ProjectionHealth::Degraded {
        valid_through_seq,
        reason,
    } = read.health
    else {
        panic!("unknown nested field must degrade the reader");
    };
    assert_eq!(valid_through_seq, 0);
    assert!(reason.contains("unknown field"), "{reason}");
    assert!(!reason.contains("event hash"), "{reason}");
}

#[cfg(unix)]
#[test]
fn typed_stream_reader_and_recovery_reject_a_symlinked_items_file() {
    use std::os::unix::fs::symlink;

    let target = tempfile::tempdir().unwrap();
    let outside = tempfile::NamedTempFile::new().unwrap();
    let run_id = crate::run_artifacts::new_run_id("symlinked-items");
    let path = crate::run_artifacts::run_dir(target.path(), &run_id).join("items.jsonl");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    symlink(outside.path(), &path).unwrap();

    let read_error = read_run_items(target.path(), &run_id).unwrap_err();
    let recovery_error = RunItemWriter::open(target.path(), &run_id, None)
        .err()
        .expect("symlinked stream must fail recovery");
    assert!(read_error.to_string().contains("symlink"));
    assert!(format!("{recovery_error:#}").contains("symlink"));
}

#[test]
fn typed_stream_reader_and_recovery_reject_oversized_streams_and_records() {
    let target = tempfile::tempdir().unwrap();
    let run_id = crate::run_artifacts::new_run_id("oversized-items");
    let path = crate::run_artifacts::run_dir(target.path(), &run_id).join("items.jsonl");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::File::create(&path)
        .unwrap()
        .set_len(MAX_RUN_ITEM_STREAM_BYTES + 1)
        .unwrap();
    assert!(read_run_items(target.path(), &run_id).is_err());
    assert!(RunItemWriter::open(target.path(), &run_id, None).is_err());

    std::fs::write(
        &path,
        vec![b'x'; MAX_SERIALIZED_RUN_ITEM_BYTES.saturating_add(1)],
    )
    .unwrap();
    let read = read_run_items(target.path(), &run_id).unwrap().unwrap();
    assert!(matches!(read.health, ProjectionHealth::Degraded { .. }));
    assert!(RunItemWriter::open(target.path(), &run_id, None).is_err());
}

#[test]
fn persistence_policy_bounds_previews_and_never_serializes_sensitive_inputs() {
    let prompt_secret = "Authorization: Bearer sk-prompt-sentinel";
    let argument_secret = "postgres://operator:password@localhost/private";
    let response_secret = "sk-model-response-sentinel";
    let preview = SafeText::preview_line(format!("{prompt_secret} {}", "x".repeat(700)));
    assert!(preview.as_str().chars().count() <= MAX_PREVIEW_LINE_CHARS);
    let item = RunItemV1::ToolCallRequested {
        tool_name: SafeText::operator_visible("security:scan"),
        operation_fingerprint: OperationFingerprint::from_bytes(
            format!("{prompt_secret}\0{argument_secret}\0{response_secret}").as_bytes(),
        ),
        safe_option_names: vec![SafeText::operator_visible("credential")],
    };
    let serialized = serde_json::to_string(&item).unwrap();
    assert!(!serialized.contains("sk-prompt-sentinel"));
    assert!(!serialized.contains(argument_secret));
    assert!(!serialized.contains(response_secret));

    let oversized = RunItemV1::ToolCallFinished {
        status: RunItemStatus::Completed,
        cost: RuntimeCostReport::UNAVAILABLE,
        result_artifact: None,
        preview: vec![SafeText::operator_visible("y".repeat(501))],
        warning_count: 0,
        error_count: 0,
    };
    assert!(RunItemPersistencePolicy::validate(&oversized).is_err());
}

#[test]
fn terminal_status_and_cost_matrix_remains_distinct_after_round_trip() {
    let exact_zero = RuntimeCostReport::known(RuntimeCost::ZERO);
    let exact_nonzero = RuntimeCostReport::known(RuntimeCost::from_usd(1.25, "test").unwrap());
    let incomplete_nonzero =
        RuntimeCostReport::incomplete(RuntimeCost::from_usd(0.75, "test").unwrap());
    let costs = [
        exact_zero,
        exact_nonzero,
        RuntimeCostReport::INCOMPLETE_ZERO,
        incomplete_nonzero,
        RuntimeCostReport::UNAVAILABLE,
    ];
    let statuses = [
        RunItemStatus::Completed,
        RunItemStatus::Partial,
        RunItemStatus::Skipped,
        RunItemStatus::Failed,
        RunItemStatus::Canceled,
        RunItemStatus::Interrupted,
    ];
    for (index, status) in statuses.into_iter().enumerate() {
        let cost = costs[index % costs.len()];
        let item = RunItemV1::TerminalOutcome {
            status,
            summary: SafeText::operator_visible(status.label()),
            cost,
            continuation: WorkflowContinuation::NoFurtherAction {
                reason: SafeText::operator_visible("matrix"),
            },
        };
        let restored: RunItemV1 =
            serde_json::from_slice(&serde_json::to_vec(&item).unwrap()).unwrap();
        let RunItemV1::TerminalOutcome {
            status: restored_status,
            cost: restored_cost,
            ..
        } = restored
        else {
            unreachable!()
        };
        assert_eq!(restored_status, status);
        assert_eq!(restored_cost, cost);
    }
}
