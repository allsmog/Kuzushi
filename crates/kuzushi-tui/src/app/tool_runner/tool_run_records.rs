use kuzushi_core::run_artifacts::{
    load_run_failures, try_record_tool_run_canceled, try_record_tool_run_complete,
    try_record_tool_run_failed, try_record_tool_run_interrupted, try_record_tool_run_refused,
    FailureToLlmContext, ToolRunRecord,
};

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
    try_record_tool_run_complete(record, result)?;
    Ok(failure_context_for_tool_run(target, run_id))
}

pub(crate) fn record_tool_run_canceled(
    target: Option<&std::path::Path>,
    run_id: Option<&str>,
    tool_name: &str,
    reason: &str,
) -> anyhow::Result<()> {
    let (Some(target), Some(run_id)) = (target, run_id) else {
        return Ok(());
    };
    try_record_tool_run_canceled(
        ToolRunRecord::new(target, run_id, "tool", tool_name),
        reason,
    )
}

pub(crate) fn record_tool_run_interrupted(
    target: Option<&std::path::Path>,
    run_id: Option<&str>,
    tool_name: &str,
    reason: &str,
) -> anyhow::Result<()> {
    let (Some(target), Some(run_id)) = (target, run_id) else {
        return Ok(());
    };
    try_record_tool_run_interrupted(
        ToolRunRecord::new(target, run_id, "tool", tool_name),
        reason,
    )
}

pub(crate) fn record_tool_run_refused(
    target: Option<&std::path::Path>,
    run_id: Option<&str>,
    tool_name: &str,
    reason: &str,
) -> anyhow::Result<()> {
    let (Some(target), Some(run_id)) = (target, run_id) else {
        return Ok(());
    };
    try_record_tool_run_refused(
        ToolRunRecord::new(target, run_id, "tool", tool_name),
        reason,
    )
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
    try_record_tool_run_failed(record, error)?;
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
