use kuzushi_core::run_artifacts::{
    load_run_failures, try_record_tool_run_canceled_observed, try_record_tool_run_canceled_settled,
    try_record_tool_run_complete_observed, try_record_tool_run_complete_settled,
    try_record_tool_run_failed_observed, try_record_tool_run_failed_settled,
    try_record_tool_run_interrupted_observed, try_record_tool_run_interrupted_settled,
    try_record_tool_run_refused_observed, try_record_tool_run_refused_settled, FailureToLlmContext,
    ToolRunRecord,
};

#[derive(Clone, Copy)]
pub(crate) enum ToolRunTerminalKind {
    Canceled,
    Interrupted,
    Refused,
}

pub(crate) fn record_tool_run_complete(
    target: Option<&std::path::Path>,
    run_id: Option<&str>,
    tool_name: &str,
    result: &serde_json::Value,
) -> anyhow::Result<Option<FailureToLlmContext>> {
    let (Some(target), Some(run_id)) = (target, run_id) else {
        return Ok(None);
    };
    let record = ToolRunRecord::new(target, run_id, "tool", tool_name);
    let observation = kuzushi_core::run_lifecycle::RunObservationHandle::jsonl(target, run_id)?;
    try_record_tool_run_complete_observed(record, result, Some(&observation))?;
    Ok(failure_context_for_tool_run(target, run_id))
}

pub(crate) fn record_tool_run_complete_settled(
    target: Option<&std::path::Path>,
    run_id: Option<&str>,
    tool_name: &str,
    result: &serde_json::Value,
    completion: kuzushi_core::PendingToolCallCompletion,
) -> anyhow::Result<Option<FailureToLlmContext>> {
    let (Some(target), Some(run_id)) = (target, run_id) else {
        completion.finish(None)?;
        return Ok(None);
    };
    let observation = settlement_observation(&completion)?;
    try_record_tool_run_complete_settled(
        ToolRunRecord::new(target, run_id, "tool", tool_name),
        result,
        &observation,
        completion,
    )?;
    Ok(failure_context_for_tool_run(target, run_id))
}

pub(crate) fn record_tool_run_terminal(
    target: Option<&std::path::Path>,
    run_id: Option<&str>,
    tool_name: &str,
    kind: ToolRunTerminalKind,
    reason: &str,
    completion: Option<kuzushi_core::PendingToolCallCompletion>,
) -> anyhow::Result<()> {
    let (Some(target), Some(run_id)) = (target, run_id) else {
        return settle_targetless_terminal(completion);
    };
    let record = ToolRunRecord::new(target, run_id, "tool", tool_name);
    match completion {
        Some(completion) => {
            let observation = settlement_observation(&completion)?;
            record_observed_terminal(record, reason, &observation, kind, completion)
        }
        None => {
            let observation =
                kuzushi_core::run_lifecycle::RunObservationHandle::jsonl(target, run_id)?;
            record_unobserved_terminal(record, reason, &observation, kind)
        }
    }
}

fn settle_targetless_terminal(
    completion: Option<kuzushi_core::PendingToolCallCompletion>,
) -> anyhow::Result<()> {
    if let Some(completion) = completion {
        completion.finish(None)?;
    }
    Ok(())
}

fn record_observed_terminal(
    record: ToolRunRecord<'_>,
    reason: &str,
    observation: &kuzushi_core::run_lifecycle::RunObservationHandle,
    kind: ToolRunTerminalKind,
    completion: kuzushi_core::PendingToolCallCompletion,
) -> anyhow::Result<()> {
    match kind {
        ToolRunTerminalKind::Canceled => {
            try_record_tool_run_canceled_settled(record, reason, observation, completion)
        }
        ToolRunTerminalKind::Interrupted => {
            try_record_tool_run_interrupted_settled(record, reason, observation, completion)
        }
        ToolRunTerminalKind::Refused => {
            try_record_tool_run_refused_settled(record, reason, observation, completion)
        }
    }
}

fn record_unobserved_terminal(
    record: ToolRunRecord<'_>,
    reason: &str,
    observation: &kuzushi_core::run_lifecycle::RunObservationHandle,
    kind: ToolRunTerminalKind,
) -> anyhow::Result<()> {
    match kind {
        ToolRunTerminalKind::Canceled => {
            try_record_tool_run_canceled_observed(record, reason, Some(observation))
        }
        ToolRunTerminalKind::Interrupted => {
            try_record_tool_run_interrupted_observed(record, reason, Some(observation))
        }
        ToolRunTerminalKind::Refused => {
            try_record_tool_run_refused_observed(record, reason, Some(observation))
        }
    }
}

pub(crate) fn record_tool_run_failed_settled(
    target: Option<&std::path::Path>,
    run_id: Option<&str>,
    tool_name: &str,
    error: &str,
    completion: kuzushi_core::PendingToolCallCompletion,
) -> anyhow::Result<Option<FailureToLlmContext>> {
    let (Some(target), Some(run_id)) = (target, run_id) else {
        completion.finish(None)?;
        return Ok(None);
    };
    let observation = settlement_observation(&completion)?;
    try_record_tool_run_failed_settled(
        ToolRunRecord::new(target, run_id, "tool", tool_name),
        error,
        &observation,
        completion,
    )?;
    Ok(failure_context_for_tool_run(target, run_id))
}

fn settlement_observation(
    completion: &kuzushi_core::PendingToolCallCompletion,
) -> anyhow::Result<kuzushi_core::run_lifecycle::RunObservationHandle> {
    completion
        .settlement_observation()
        .ok_or_else(|| anyhow::anyhow!("observed tool completion has no settlement observation"))
}

pub(crate) fn record_tool_run_failed(
    target: Option<&std::path::Path>,
    run_id: Option<&str>,
    tool_name: &str,
    error: &str,
) -> anyhow::Result<Option<FailureToLlmContext>> {
    let (Some(target), Some(run_id)) = (target, run_id) else {
        return Ok(None);
    };
    let record = ToolRunRecord::new(target, run_id, "tool", tool_name);
    let observation = kuzushi_core::run_lifecycle::RunObservationHandle::jsonl(target, run_id)?;
    try_record_tool_run_failed_observed(record, error, Some(&observation))?;
    Ok(failure_context_for_tool_run(target, run_id))
}

pub(crate) fn render_failure_context(context: &FailureToLlmContext) -> String {
    format!(
        "stage: {} | cause: {} | allowed proof: {} | missing: {} | recovery: {} | inspect next: {} | forbidden claims: {}",
        failure_stage(context),
        truncate_context_text(failure_cause(context), 160),
        context.allowed_proof_level,
        compact_context_list(&context.missing_artifacts, 4),
        compact_context_list(&context.recovery_options, 2),
        compact_context_list(&context.next_files_or_artifacts_to_inspect, 3),
        compact_context_list(&context.claims_forbidden, 8),
    )
}

fn failure_stage(context: &FailureToLlmContext) -> &str {
    if context.failed_stage.is_empty() {
        "unknown"
    } else {
        &context.failed_stage
    }
}

fn failure_cause(context: &FailureToLlmContext) -> &str {
    if context.cause.is_empty() {
        &context.what_failed
    } else {
        &context.cause
    }
}

fn failure_context_for_tool_run(
    target: &std::path::Path,
    run_id: &str,
) -> Option<FailureToLlmContext> {
    load_run_failures(target, run_id)
        .ok()?
        .failures
        .into_iter()
        .next()
        .map(|failure| failure.agent_thread_context)
}

fn compact_context_list(values: &[String], limit: usize) -> String {
    if values.is_empty() {
        return "none".to_string();
    }
    let mut items = values.iter().take(limit).cloned().collect::<Vec<_>>();
    if values.len() > limit {
        items.push(format!("+{} more", values.len() - limit));
    }
    items.join(", ")
}

fn truncate_context_text(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    format!("{}...", text.chars().take(max_chars).collect::<String>())
}
