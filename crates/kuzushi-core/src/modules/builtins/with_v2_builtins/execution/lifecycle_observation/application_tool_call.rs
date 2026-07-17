use super::*;

impl ApplicationToolCall {
    /// Record an application-owned call that policy rejected before executor
    /// invocation. The call remains pending until the application has made its
    /// failure result durable, so the one finish item can carry the exact
    /// correlated artifact reference. No `ToolCallStarted` item is emitted.
    pub fn reject_before_start(
        observation: RunObservationHandle,
        tool_name: &str,
        input: &Value,
        reason_class: &str,
        detail: &str,
    ) -> Result<PendingToolCallCompletion> {
        let identity = application_call_identity(&observation)?;
        emit_application_call_requested(&observation, identity, tool_name, input)?;
        Ok(rejected_completion(
            observation,
            identity,
            reason_class,
            detail,
        ))
    }

    pub fn start(
        observation: RunObservationHandle,
        tool_name: &str,
        input: &Value,
        runtime: Option<&str>,
        model: Option<&str>,
    ) -> Result<Self> {
        let identity = application_call_identity(&observation)?;
        emit_application_call_requested(&observation, identity, tool_name, input)?;
        emit_application_call_started(&observation, identity, tool_name, runtime, model)?;
        Ok(Self {
            observation,
            identity,
        })
    }

    pub fn completion_from_result(self, result: &Result<Value>) -> PendingToolCallCompletion {
        let (status, cost, preview, warning_count, error_count) = result_fields(result);
        self.completion(status, cost, preview, warning_count, error_count)
    }

    pub fn completion(
        self,
        status: RunItemStatus,
        cost: RuntimeCostReport,
        preview: Vec<SafeText>,
        warning_count: u64,
        error_count: u64,
    ) -> PendingToolCallCompletion {
        PendingToolCallCompletion {
            observation: Some(self.observation),
            identity: Some(self.identity),
            status,
            cost,
            preview,
            warning_count,
            error_count,
            execution_may_have_occurred: true,
        }
    }

    pub fn observation(&self) -> &RunObservationHandle {
        &self.observation
    }

    /// Scope executor-owned child activity beneath this exact tool call.
    pub fn execution_observation(&self) -> RunObservationHandle {
        self.observation.with_parent(self.identity.item_id)
    }
}

fn rejected_completion(
    observation: RunObservationHandle,
    identity: ToolCallIdentity,
    reason_class: &str,
    detail: &str,
) -> PendingToolCallCompletion {
    PendingToolCallCompletion {
        observation: Some(observation),
        identity: Some(identity),
        status: RunItemStatus::Failed,
        cost: RuntimeCostReport::UNAVAILABLE,
        preview: vec![SafeText::preview_line(format!(
            "request rejected before execution ({reason_class}): {detail}"
        ))],
        warning_count: 0,
        error_count: 1,
        execution_may_have_occurred: false,
    }
}

fn application_call_identity(observation: &RunObservationHandle) -> Result<ToolCallIdentity> {
    let task_id = observation
        .inheritable_dispatch_task_id()
        .ok_or_else(|| anyhow::anyhow!("application call lacks a semantic task scope"))?;
    Ok(ToolCallIdentity {
        call_id: RunCallId::new(),
        item_id: RunItemId::new(),
        task_id,
        parent_item_id: observation.parent_item_id(),
    })
}

fn emit_application_call_requested(
    observation: &RunObservationHandle,
    identity: ToolCallIdentity,
    tool_name: &str,
    input: &Value,
) -> Result<()> {
    let safe_option_names = safe_option_names(input);
    let fingerprint = OperationFingerprint::from_bytes(&serde_json::to_vec(input)?);
    observation.emit(
        RunItemRecord::new(
            identity.item_id,
            RunItemSource::Dispatch,
            RunItemV1::ToolCallRequested {
                tool_name: SafeText::operator_visible(tool_name),
                operation_fingerprint: fingerprint,
                safe_option_names,
            },
        )
        .with_call(identity.call_id),
    )
}

fn safe_option_names(input: &Value) -> Vec<SafeText> {
    input
        .as_object()
        .into_iter()
        .flat_map(|object| object.keys())
        .take(128)
        .map(SafeText::operator_visible)
        .collect()
}

fn emit_application_call_started(
    observation: &RunObservationHandle,
    identity: ToolCallIdentity,
    tool_name: &str,
    runtime: Option<&str>,
    model: Option<&str>,
) -> Result<()> {
    observation
        .emit_and_flush(
            RunItemRecord::new(
                identity.item_id,
                RunItemSource::Dispatch,
                RunItemV1::ToolCallStarted {
                    tool_name: SafeText::operator_visible(tool_name),
                    runtime: runtime.map(SafeText::operator_visible),
                    model: model.map(SafeText::operator_visible),
                },
            )
            .with_call(identity.call_id),
        )
        .map(drop)
}
