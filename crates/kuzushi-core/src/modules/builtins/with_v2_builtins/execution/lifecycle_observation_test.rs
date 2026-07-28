use super::*;
use crate::run_lifecycle::{
    read_run_items, ArtifactReference, ProjectionHealth, RunItemEnvelopeV1, RunItemId,
    RunItemSource, RunItemStatus, RunItemV1, RunObservationHandle, RunTaskHandle, RunTaskId,
    SafeText,
};
use crate::V2Config;
use serde_json::{json, Value};
use std::collections::HashSet;

const SEMANTIC_TASK: &str = "verify applied patch";

fn context<'a>(
    config: &'a V2Config,
    trace: &'a crate::run_artifacts::TraceHandle,
) -> ToolExecutionContext<'a> {
    ToolExecutionContext {
        config,
        workspace: None,
        findings_store: None,
        trace: Some(trace),
        cancellation: None,
        authorization: Default::default(),
    }
}

fn start_semantic_task(target: &tempfile::TempDir, run_id: &str) -> (RunTaskHandle, RunTaskId) {
    let task_id = RunTaskId::new();
    let task_observation = RunObservationHandle::jsonl(target.path(), run_id)
        .unwrap()
        .start_root_task_with_id(task_id, SEMANTIC_TASK)
        .unwrap();
    let task = task_observation.task_handle().unwrap();
    task.update(RunItemStatus::Running, Some("executing verification"))
        .unwrap();
    (task, task_id)
}

fn request_and_start(
    ctx: &ToolExecutionContext<'_>,
    tool_name: &str,
    binding: [u8; 32],
    input: Value,
) -> DispatchLifecycle {
    let lifecycle =
        DispatchLifecycle::requested(ctx, tool_name, binding, &input, false, true).unwrap();
    lifecycle.started(&input, ctx).unwrap();
    lifecycle
}

fn finish_success(lifecycle: DispatchLifecycle, summary: &str) -> ToolCallIdentity {
    lifecycle
        .pending_completion(&Ok(json!({
            "status": "completed",
            "summary": summary,
        })))
        .finish(None)
        .unwrap()
        .unwrap()
}

fn task_updates(items: &[RunItemEnvelopeV1]) -> Vec<&RunItemEnvelopeV1> {
    items
        .iter()
        .filter(|envelope| matches!(envelope.item, RunItemV1::TaskUpdated { .. }))
        .collect()
}

fn call_items<'a>(
    items: &'a [RunItemEnvelopeV1],
    identity: ToolCallIdentity,
) -> Vec<&'a RunItemEnvelopeV1> {
    items
        .iter()
        .filter(|envelope| envelope.call_id == Some(identity.call_id))
        .collect()
}

fn assert_workflow_owns_only_semantic_task(
    items: &[RunItemEnvelopeV1],
    expected_task_id: RunTaskId,
) {
    let updates = task_updates(items);
    assert_eq!(
        updates.len(),
        3,
        "pending, running, and completed task rows"
    );
    assert!(updates.iter().all(|envelope| {
        envelope.source == RunItemSource::Workflow
            && envelope.task_id == Some(expected_task_id)
            && matches!(
                &envelope.item,
                RunItemV1::TaskUpdated { title, .. } if title.as_str() == SEMANTIC_TASK
            )
    }));
    let task_ids = items
        .iter()
        .filter_map(|envelope| envelope.task_id)
        .collect::<HashSet<_>>();
    assert_eq!(task_ids, HashSet::from([expected_task_id]));
}

fn result_artifact(producing_item_id: RunItemId) -> ArtifactReference {
    ArtifactReference {
        path: SafeText::operator_visible("result.json"),
        kind: SafeText::operator_visible("tool_result"),
        label: SafeText::operator_visible("normalized tool result"),
        digest: SafeText::operator_visible(format!("sha256:{}", "a".repeat(64))),
        byte_count: 128,
        line_count: Some(1),
        producing_item_id,
    }
}

#[test]
fn taskless_single_tool_dispatch_keeps_one_correlated_call_without_fake_task() {
    let target = tempfile::tempdir().unwrap();
    let run_id = "tool-unscoped-dispatch-test";
    let trace = RunObservationHandle::jsonl(target.path(), run_id)
        .unwrap()
        .trace_handle();
    let config = V2Config::default();

    let lifecycle = request_and_start(
        &context(&config, &trace),
        "sast:scan",
        [3; 32],
        json!({"tasks": ["secret-scan"]}),
    );
    lifecycle
        .execution_trace()
        .unwrap()
        .step("tool-progress", "scan", "Running secret scan")
        .emit();
    let identity = finish_success(lifecycle, "clean");

    let read = read_run_items(target.path(), run_id).unwrap().unwrap();
    let calls = call_items(&read.items, identity);
    assert_eq!(identity.task_id, None);
    assert_eq!(calls.len(), 4);
    assert!(calls.iter().all(|item| item.task_id.is_none()));
    assert!(!read.items.iter().any(|item| matches!(
        item.item,
        RunItemV1::TaskUpdated { .. } | RunItemV1::PlanUpdated { .. }
    )));
}

#[test]
fn workflow_task_owns_root_call_without_phantom_tool_task() {
    let target = tempfile::tempdir().unwrap();
    let run_id = "tool-workflow-owned-task-test";
    let (task, task_id) = start_semantic_task(&target, run_id);
    let trace = task.observation().trace_handle();
    let config = V2Config::default();
    let identity = finish_success(
        request_and_start(
            &context(&config, &trace),
            "secret-scan:scan",
            [4; 32],
            json!({"target": "."}),
        ),
        "clean",
    );
    task.update_and_flush(RunItemStatus::Completed, Some("verification complete"))
        .unwrap();

    let read = read_run_items(target.path(), run_id).unwrap().unwrap();
    assert_eq!(read.health, ProjectionHealth::Healthy);
    assert_eq!(
        read.items
            .iter()
            .filter(|envelope| matches!(envelope.item, RunItemV1::PlanUpdated { .. }))
            .count(),
        1
    );
    assert_workflow_owns_only_semantic_task(&read.items, task_id);
    assert_eq!(identity.task_id, Some(task_id));
    assert!(identity.parent_item_id.is_none());
    let calls = call_items(&read.items, identity);
    assert_eq!(
        calls.len(),
        3,
        "requested, started, and finished call items"
    );
    assert!(calls.iter().all(|envelope| {
        envelope.source == RunItemSource::Dispatch
            && envelope.task_id == Some(task_id)
            && envelope.item_id == identity.item_id
            && envelope.parent_item_id.is_none()
    }));
}

#[test]
fn nested_dispatch_inherits_semantic_task_and_only_parents_calls() {
    let target = tempfile::tempdir().unwrap();
    let run_id = "tool-nested-dispatch-test";
    let (task, task_id) = start_semantic_task(&target, run_id);
    let root_trace = task.observation().trace_handle();
    let config = V2Config::default();
    let parent = request_and_start(
        &context(&config, &root_trace),
        "patch:reverify",
        [1; 32],
        json!({"applicationId": "application-1"}),
    );
    let nested_trace = parent.execution_trace().unwrap();
    let nested = request_and_start(
        &context(&config, &nested_trace),
        "secret-scan:scan",
        [2; 32],
        json!({"target": "."}),
    );
    let nested_identity = finish_success(nested, "clean");
    let parent_identity = finish_success(parent, "verified");
    task.update_and_flush(RunItemStatus::Completed, Some("verification complete"))
        .unwrap();

    let read = read_run_items(target.path(), run_id).unwrap().unwrap();
    assert_eq!(read.health, ProjectionHealth::Healthy);
    assert_workflow_owns_only_semantic_task(&read.items, task_id);
    assert_eq!(parent_identity.task_id, Some(task_id));
    assert_eq!(nested_identity.task_id, Some(task_id));
    assert!(parent_identity.parent_item_id.is_none());
    assert_eq!(
        nested_identity.parent_item_id,
        Some(parent_identity.item_id)
    );
    assert!(call_items(&read.items, parent_identity)
        .iter()
        .all(|envelope| envelope.parent_item_id.is_none()));
    assert!(call_items(&read.items, nested_identity)
        .iter()
        .all(|envelope| envelope.parent_item_id == Some(parent_identity.item_id)));
}

#[test]
fn tool_call_started_is_durable_before_executor_completion() {
    let target = tempfile::tempdir().unwrap();
    let run_id = "tool-started-durability-test";
    let (task, task_id) = start_semantic_task(&target, run_id);
    let trace = task.observation().trace_handle();
    let config = V2Config::default();
    let lifecycle = request_and_start(
        &context(&config, &trace),
        "secret-scan:scan",
        [5; 32],
        json!({"target": "."}),
    );

    let read = read_run_items(target.path(), run_id).unwrap().unwrap();
    assert_eq!(read.health, ProjectionHealth::Healthy);
    let calls = read
        .items
        .iter()
        .filter(|envelope| envelope.call_id == Some(lifecycle.call_id))
        .collect::<Vec<_>>();
    assert_eq!(calls.len(), 2, "request and start must be durable together");
    assert!(matches!(calls[0].item, RunItemV1::ToolCallRequested { .. }));
    assert!(matches!(calls[1].item, RunItemV1::ToolCallStarted { .. }));
    assert!(calls.iter().all(|envelope| {
        envelope.item_id == lifecycle.call_item_id && envelope.task_id == Some(task_id)
    }));
    assert!(!read
        .items
        .iter()
        .any(|envelope| matches!(envelope.item, RunItemV1::ToolCallFinished { .. })));

    finish_success(lifecycle, "clean");
}

#[test]
fn execution_trace_bridges_safe_progress_into_the_owning_call() {
    let target = tempfile::tempdir().unwrap();
    let run_id = "tool-progress-bridge-test";
    let (task, task_id) = start_semantic_task(&target, run_id);
    let trace = task.observation().trace_handle();
    let config = V2Config::default();
    let lifecycle = request_and_start(
        &context(&config, &trace),
        "secret-scan:scan",
        [9; 32],
        json!({"target": "."}),
    );
    let execution = lifecycle.execution_trace().unwrap();
    execution
        .step("tool-progress", "scan", "Indexing repository files")
        .with_progress(421, 832)
        .emit();
    execution
        .step(
            "reasoning",
            "scan",
            "Comparing candidate source-to-sink paths",
        )
        .emit();
    let identity = finish_success(lifecycle, "7 findings");

    let read = read_run_items(target.path(), run_id).unwrap().unwrap();
    let calls = call_items(&read.items, identity);
    assert!(calls.iter().any(|envelope| matches!(
        envelope.item,
        RunItemV1::ToolCallProgress {
            completed: Some(421),
            total: Some(832),
            ..
        }
    )));
    assert!(calls
        .iter()
        .any(|envelope| matches!(envelope.item, RunItemV1::SafeReasoningSummary { .. })));
    assert_eq!(
        calls
            .iter()
            .filter(|envelope| matches!(envelope.item, RunItemV1::ToolCallFinished { .. }))
            .count(),
        1
    );
    assert!(calls
        .iter()
        .all(|envelope| envelope.task_id == Some(task_id)));
    assert!(calls.iter().all(|envelope| match envelope.item {
        RunItemV1::ToolCallProgress { .. } | RunItemV1::SafeReasoningSummary { .. } => {
            envelope.parent_item_id == Some(identity.item_id)
        }
        _ => envelope.parent_item_id.is_none(),
    }));
}

#[test]
fn deferred_dispatch_rejection_settles_once_with_exact_result_linkage() {
    let target = tempfile::tempdir().unwrap();
    let run_id = "tool-rejected-identity-test";
    let (task, task_id) = start_semantic_task(&target, run_id);
    let trace = task.observation().trace_handle();
    let config = V2Config::default();
    let lifecycle = DispatchLifecycle::requested(
        &context(&config, &trace),
        "patch:finding",
        [8; 32],
        &json!({"findingId": "F-1"}),
        false,
        true,
    )
    .unwrap();

    let outcome = lifecycle
        .rejected(anyhow::anyhow!("operator authorization required"))
        .unwrap();
    assert!(outcome.execution.is_err());
    assert!(!outcome.completion.execution_may_have_occurred());
    let identity = outcome.completion.identity().unwrap();
    outcome
        .completion
        .finish(Some(result_artifact(identity.item_id)))
        .unwrap();
    assert_eq!(identity.task_id, Some(task_id));

    let read = read_run_items(target.path(), run_id).unwrap().unwrap();
    let calls = call_items(&read.items, identity);
    assert_eq!(
        calls.len(),
        3,
        "request, rejection, and finish must be durable"
    );
    assert!(matches!(calls[1].item, RunItemV1::ToolCallRejected { .. }));
    assert!(matches!(
        calls[2].item,
        RunItemV1::ToolCallFinished {
            status: RunItemStatus::Blocked,
            result_artifact: Some(_),
            ..
        }
    ));
    assert!(!calls
        .iter()
        .any(|item| matches!(item.item, RunItemV1::ToolCallStarted { .. })));
    let projection = crate::run_lifecycle::load_run_projection(target.path(), run_id)
        .unwrap()
        .projection;
    assert_eq!(
        projection.calls[&identity.call_id]
            .result_artifact
            .as_ref()
            .map(|artifact| artifact.producing_item_id),
        Some(identity.item_id)
    );
}

#[test]
fn application_rejection_settles_once_with_exact_durable_result() {
    let target = tempfile::tempdir().unwrap();
    let run_id = "application-rejection-result-test";
    let (task, task_id) = start_semantic_task(&target, run_id);
    let observation = task.observation();
    let completion = ApplicationToolCall::reject_before_start(
        observation,
        "sast:scan",
        &json!({"unknown": true}),
        "preparation_policy",
        "unknown option",
    )
    .unwrap();
    let identity = completion.identity().unwrap();
    completion
        .finish(Some(result_artifact(identity.item_id)))
        .unwrap();

    let read = read_run_items(target.path(), run_id).unwrap().unwrap();
    let calls = call_items(&read.items, identity);
    assert_eq!(
        calls.len(),
        3,
        "request, rejection, and finish must be durable"
    );
    assert!(matches!(calls[0].item, RunItemV1::ToolCallRequested { .. }));
    assert!(matches!(calls[1].item, RunItemV1::ToolCallRejected { .. }));
    assert!(matches!(
        calls[2].item,
        RunItemV1::ToolCallFinished {
            status: RunItemStatus::Blocked,
            result_artifact: Some(_),
            ..
        }
    ));
    assert_eq!(calls[2].task_id, Some(task_id));
    assert!(!calls
        .iter()
        .any(|item| matches!(item.item, RunItemV1::ToolCallStarted { .. })));

    let projection = crate::run_lifecycle::load_run_projection(target.path(), run_id)
        .unwrap()
        .projection;
    assert_eq!(
        projection.calls[&identity.call_id]
            .result_artifact
            .as_ref()
            .map(|artifact| artifact.producing_item_id),
        Some(identity.item_id)
    );
}

#[test]
fn result_artifact_requires_exact_producing_call_identity() {
    let target = tempfile::tempdir().unwrap();
    let run_id = "tool-result-artifact-identity-test";
    let (task, _) = start_semantic_task(&target, run_id);
    let trace = task.observation().trace_handle();
    let config = V2Config::default();
    let completion = request_and_start(
        &context(&config, &trace),
        "secret-scan:scan",
        [6; 32],
        json!({"target": "."}),
    )
    .pending_completion(&Ok(json!({"status": "completed", "summary": "clean"})));
    let identity = completion.identity().unwrap();

    let error = completion
        .finish(Some(result_artifact(RunItemId::new())))
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("result artifact is scoped to a different call"),
        "{error}"
    );

    let completion = request_and_start(
        &context(&config, &trace),
        "secret-scan:scan",
        [7; 32],
        json!({"target": "."}),
    )
    .pending_completion(&Ok(json!({"status": "completed", "summary": "clean"})));
    let exact_identity = completion.identity().unwrap();
    completion
        .finish(Some(result_artifact(exact_identity.item_id)))
        .unwrap();

    let read = read_run_items(target.path(), run_id).unwrap().unwrap();
    assert_eq!(read.health, ProjectionHealth::Healthy);
    assert!(!read.items.iter().any(|envelope| {
        envelope.call_id == Some(identity.call_id)
            && matches!(envelope.item, RunItemV1::ToolCallFinished { .. })
    }));
    let artifact = read
        .items
        .iter()
        .find_map(|envelope| {
            if envelope.call_id != Some(exact_identity.call_id) {
                return None;
            }
            let RunItemV1::ToolCallFinished {
                result_artifact: Some(artifact),
                ..
            } = &envelope.item
            else {
                return None;
            };
            Some(artifact)
        })
        .expect("matching completion must persist its exact result artifact");
    assert_eq!(artifact.producing_item_id, exact_identity.item_id);
}
