use super::*;
use crate::run_lifecycle::{
    PersistenceFailureStage, RunItemStatus, RunItemV1, RunItemWriterFault, SafeText,
};
use crate::runtime::RuntimeCostReport;

#[test]
fn completion_fallback_preserves_pre_and_post_dispatch_truth() {
    assert_eq!(
        completion_failure_context(&None, false),
        (RunItemStatus::Failed, false)
    );
    assert_eq!(
        completion_failure_context(&None, true),
        (RunItemStatus::Failed, true)
    );
}

#[test]
fn writer_fault_annotation_forbids_only_post_dispatch_retry() {
    let fault = || RunItemWriterFault {
        stage: PersistenceFailureStage::Sync,
        last_durable_seq: 4,
        detail: SafeText::operator_visible("sync failed"),
        execution_may_have_occurred: false,
    };

    let before = annotate_writer_fault(anyhow::Error::new(fault()), false);
    let after = annotate_writer_fault(anyhow::Error::new(fault()), true);
    let before = before.downcast_ref::<RunItemWriterFault>().unwrap();
    let after = after.downcast_ref::<RunItemWriterFault>().unwrap();

    assert!(!before.execution_may_have_occurred);
    assert!(!before.detail.as_str().contains("do not retry"));
    assert!(after.execution_may_have_occurred);
    assert!(after.detail.as_str().contains("do not retry automatically"));
}

#[test]
fn terminal_persistence_scopes_result_artifact_to_its_exact_call() {
    let mut fixture = ObservedTerminalFixture::new("artifact-call-scope", RunItemStatus::Completed);
    let completion = fixture.take_completion();
    try_record_tool_run_complete_settled(
        fixture.record(),
        &json!({"ok": true, "status": "completed", "data": {}}),
        &fixture.observation,
        completion,
    )
    .unwrap();

    let read = crate::run_lifecycle::read_run_items(fixture.target.path(), &fixture.run_id)
        .unwrap()
        .unwrap();
    let finished = result_call_finish(&read.items);
    let produced = result_artifact_event(&read.items);
    let RunItemV1::ArtifactProduced { artifact } = &produced.item else {
        unreachable!("matched result artifact above")
    };

    assert_eq!(produced.call_id, finished.call_id);
    assert_eq!(artifact.producing_item_id, finished.item_id);
}

fn result_call_finish(
    items: &[crate::run_lifecycle::RunItemEnvelopeV1],
) -> &crate::run_lifecycle::RunItemEnvelopeV1 {
    items
        .iter()
        .find(|envelope| {
            matches!(
                &envelope.item,
                RunItemV1::ToolCallFinished {
                    result_artifact: Some(_),
                    ..
                }
            )
        })
        .expect("fixture must settle one correlated result")
}

fn result_artifact_event(
    items: &[crate::run_lifecycle::RunItemEnvelopeV1],
) -> &crate::run_lifecycle::RunItemEnvelopeV1 {
    items
        .iter()
        .find(|envelope| {
            matches!(
                &envelope.item,
                RunItemV1::ArtifactProduced { artifact }
                    if artifact.path.as_str() == "result.json"
            )
        })
        .expect("fixture must emit its correlated result artifact")
}

#[test]
fn canceled_summary_is_durable_before_the_single_call_finish() {
    let mut fixture = ObservedTerminalFixture::new("canceled-order", RunItemStatus::Canceled);
    let completion = fixture.take_completion();
    try_record_tool_run_canceled_settled(
        fixture.record(),
        "operator canceled",
        &fixture.observation,
        completion,
    )
    .unwrap();

    let summary = load_run_summary(fixture.target.path(), &fixture.run_id).unwrap();
    assert_eq!(summary.status, "canceled");
    let read = crate::run_lifecycle::read_run_items(fixture.target.path(), &fixture.run_id)
        .unwrap()
        .unwrap();
    let call_finish = item_sequence(&read.items, |item| {
        matches!(item, RunItemV1::ToolCallFinished { .. })
    });
    let terminal = item_sequence(&read.items, |item| {
        matches!(item, RunItemV1::TerminalOutcome { .. })
    });
    assert!(call_finish < terminal);
}

#[cfg(unix)]
#[test]
fn canceled_summary_failure_forces_partial_inspection_settlement() {
    use std::os::unix::fs::PermissionsExt;

    let mut fixture =
        ObservedTerminalFixture::new("canceled-summary-failure", RunItemStatus::Canceled);
    let completion = fixture.take_completion();
    let run_dir = crate::run_artifacts::run_dir(fixture.target.path(), &fixture.run_id);
    std::fs::File::create(run_dir.join(".terminal.lock")).unwrap();
    std::fs::set_permissions(&run_dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let result = try_record_tool_run_canceled_settled(
        fixture.record(),
        "operator canceled",
        &fixture.observation,
        completion,
    );
    std::fs::set_permissions(&run_dir, std::fs::Permissions::from_mode(0o700)).unwrap();

    assert!(result.is_err());
    assert_eq!(
        load_run_summary(fixture.target.path(), &fixture.run_id)
            .unwrap()
            .status,
        "running"
    );
    let read =
        crate::run_lifecycle::load_run_projection(fixture.target.path(), &fixture.run_id).unwrap();
    assert_eq!(
        read.projection.terminal.as_ref().map(|value| value.status),
        Some(RunItemStatus::Partial)
    );
    assert!(read
        .projection
        .calls
        .values()
        .all(|call| { call.status == RunItemStatus::Partial && call.result_artifact.is_none() }));
}

struct ObservedTerminalFixture {
    target: tempfile::TempDir,
    run_id: String,
    observation: crate::run_lifecycle::RunObservationHandle,
    completion: Option<crate::modules::PendingToolCallCompletion>,
}

impl ObservedTerminalFixture {
    fn new(label: &str, status: RunItemStatus) -> Self {
        let target = tempfile::tempdir().unwrap();
        let run_id = crate::run_artifacts::new_run_id(label);
        let record = ToolRunRecord::new(target.path(), &run_id, "tool", "security:scan");
        try_record_tool_run_started_with_reproducibility(
            record,
            &json!({}),
            None,
            None,
            Vec::new(),
        )
        .unwrap();
        let observation = crate::run_lifecycle::RunObservationHandle::jsonl(target.path(), &run_id)
            .unwrap()
            .start_root_task("Inspect the selected target")
            .unwrap();
        observation
            .task_handle()
            .unwrap()
            .update_and_flush(RunItemStatus::Running, None)
            .unwrap();
        let call = crate::modules::ApplicationToolCall::start(
            observation.clone(),
            "security:scan",
            &json!({}),
            None,
            None,
        )
        .unwrap();
        let completion = call.completion(status, RuntimeCostReport::UNAVAILABLE, Vec::new(), 0, 1);
        Self {
            target,
            run_id,
            observation,
            completion: Some(completion),
        }
    }

    fn record(&self) -> ToolRunRecord<'_> {
        ToolRunRecord::new(self.target.path(), &self.run_id, "tool", "security:scan")
    }

    fn take_completion(&mut self) -> crate::modules::PendingToolCallCompletion {
        self.completion
            .take()
            .expect("fixture completion is available")
    }
}

fn item_sequence(
    items: &[crate::run_lifecycle::RunItemEnvelopeV1],
    predicate: impl Fn(&RunItemV1) -> bool,
) -> u64 {
    items
        .iter()
        .find(|item| predicate(&item.item))
        .map(|item| item.seq)
        .unwrap()
}
