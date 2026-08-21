use super::*;
use crate::run_lifecycle::{
    OperationFingerprint, RunCallId, RunItemId, RunItemRecord, RunItemSource, RunItemStatus,
    RunItemV1, RunObservationHandle, SafeText,
};
use crate::runtime::RuntimeCostReport;

#[path = "lifecycle_observation/pending_completion.rs"]
mod pending_completion;
use pending_completion::result_fields;

#[path = "lifecycle_observation/application_tool_call.rs"]
mod application_tool_call;

pub(super) struct DispatchLifecycle {
    observation: Option<RunObservationHandle>,
    task_id: Option<crate::run_lifecycle::RunTaskId>,
    call_id: RunCallId,
    call_item_id: RunItemId,
    tool_name: String,
    runtime_present: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolCallIdentity {
    pub call_id: RunCallId,
    pub item_id: RunItemId,
    pub task_id: Option<crate::run_lifecycle::RunTaskId>,
    pub parent_item_id: Option<RunItemId>,
}

#[must_use = "an application-owned tool call must be converted into a pending completion"]
pub struct ApplicationToolCall {
    observation: RunObservationHandle,
    identity: ToolCallIdentity,
}

#[must_use = "a completed executor call must be settled into the typed lifecycle"]
pub struct PendingToolCallCompletion {
    observation: Option<RunObservationHandle>,
    identity: Option<ToolCallIdentity>,
    status: RunItemStatus,
    cost: RuntimeCostReport,
    preview: Vec<SafeText>,
    warning_count: u64,
    error_count: u64,
    execution_may_have_occurred: bool,
}

impl DispatchLifecycle {
    pub(super) fn requested(
        ctx: &ToolExecutionContext<'_>,
        tool_name: &str,
        operation_binding: [u8; 32],
        input: &Value,
        runtime_present: bool,
        require_observation: bool,
    ) -> Result<Self> {
        let inherited_observation = ctx.run_observation();
        anyhow::ensure!(
            !require_observation || inherited_observation.is_some(),
            "observed dispatch lacks a run observation"
        );
        let task_id = inherited_observation
            .as_ref()
            .and_then(RunObservationHandle::inheritable_dispatch_task_id);
        let lifecycle = Self {
            observation: inherited_observation,
            task_id,
            call_id: RunCallId::new(),
            call_item_id: RunItemId::new(),
            tool_name: tool_name.to_string(),
            runtime_present,
        };
        lifecycle.emit_request(operation_binding, input)?;
        Ok(lifecycle)
    }

    pub(super) fn rejected(self, error: anyhow::Error) -> Result<ObservedDispatchOutcome> {
        let reason_class = crate::runtime::runtime_failure_metadata(&error)
            .map(|metadata| metadata.error_class.as_str())
            .unwrap_or("dispatch_policy");
        self.emit_rejection(reason_class, &error.to_string())?;
        let completion = self.rejected_completion();
        Ok(ObservedDispatchOutcome {
            execution: Err(error),
            completion,
        })
    }

    pub(super) fn started(&self, input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<()> {
        let runtime = self
            .runtime_present
            .then(|| SafeText::operator_visible("agent"));
        let model = crate::modules::tool_execution_model(&self.tool_name, input, ctx.config)
            .map(SafeText::operator_visible);
        self.emit_and_flush(
            RunItemRecord::new(
                self.call_item_id,
                RunItemSource::Dispatch,
                RunItemV1::ToolCallStarted {
                    tool_name: SafeText::operator_visible(&self.tool_name),
                    runtime,
                    model,
                },
            )
            .with_call(self.call_id),
        )
    }

    pub(super) fn pending_completion(self, result: &Result<Value>) -> PendingToolCallCompletion {
        let (status, cost, preview, warning_count, error_count) = result_fields(result);
        let identity = self
            .observation
            .as_ref()
            .map(|observation| ToolCallIdentity {
                call_id: self.call_id,
                item_id: self.call_item_id,
                task_id: self.task_id,
                parent_item_id: observation.parent_item_id(),
            });
        PendingToolCallCompletion {
            observation: self.observation,
            identity,
            status,
            cost,
            preview,
            warning_count,
            error_count,
            execution_may_have_occurred: true,
        }
    }

    pub(super) fn execution_trace(&self) -> Option<crate::run_artifacts::TraceHandle> {
        self.observation.as_ref().map(|observation| {
            observation
                .for_call_progress(self.call_id, self.call_item_id)
                .with_parent(self.call_item_id)
                .trace_handle()
        })
    }

    fn emit_request(&self, operation_binding: [u8; 32], input: &Value) -> Result<()> {
        let safe_option_names = input
            .as_object()
            .into_iter()
            .flat_map(|object| object.keys())
            .take(128)
            .map(SafeText::operator_visible)
            .collect();
        self.emit(
            RunItemRecord::new(
                self.call_item_id,
                RunItemSource::Dispatch,
                RunItemV1::ToolCallRequested {
                    tool_name: SafeText::operator_visible(&self.tool_name),
                    operation_fingerprint: OperationFingerprint::from_digest(operation_binding),
                    safe_option_names,
                },
            )
            .with_call(self.call_id),
        )
    }

    fn emit_rejection(&self, reason_class: &str, detail: &str) -> Result<()> {
        self.emit_and_flush(
            RunItemRecord::new(
                self.call_item_id,
                RunItemSource::Dispatch,
                RunItemV1::ToolCallRejected {
                    reason_class: SafeText::operator_visible(reason_class),
                    detail: SafeText::condensed_line(detail),
                },
            )
            .with_call(self.call_id),
        )
    }

    fn emit(&self, record: RunItemRecord) -> Result<()> {
        if let Some(observation) = self.observation.as_ref() {
            observation.emit(record)?;
        }
        Ok(())
    }

    fn emit_and_flush(&self, record: RunItemRecord) -> Result<()> {
        if let Some(observation) = self.observation.as_ref() {
            observation.emit_and_flush(record)?;
        }
        Ok(())
    }

    fn rejected_completion(self) -> PendingToolCallCompletion {
        let identity = self
            .observation
            .as_ref()
            .map(|observation| ToolCallIdentity {
                call_id: self.call_id,
                item_id: self.call_item_id,
                task_id: self.task_id,
                parent_item_id: observation.parent_item_id(),
            });
        PendingToolCallCompletion {
            observation: self.observation,
            identity,
            status: RunItemStatus::Blocked,
            cost: RuntimeCostReport::UNAVAILABLE,
            preview: vec![SafeText::preview_line(
                "request rejected before execution (dispatch_policy)",
            )],
            warning_count: 0,
            error_count: 1,
            execution_may_have_occurred: false,
        }
    }
}

#[cfg(test)]
#[path = "lifecycle_observation_test.rs"]
mod tests;
