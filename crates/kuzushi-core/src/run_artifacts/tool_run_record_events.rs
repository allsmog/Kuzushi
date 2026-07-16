use super::tool_run_record::ToolRunRecord;
use super::*;

pub(crate) fn append_started_event(
    record: ToolRunRecord<'_>,
    artifact: Option<RunArtifact>,
) -> Result<()> {
    let mut event = RunEvent::new(
        next_run_event_number(record.target, record.run_id),
        record.kind,
        "started",
        format!("{} started", record.tool),
    )
    .with_tool(record.tool);
    if let Some(artifact) = artifact {
        event = event.with_artifact(artifact);
    }
    append_run_event(record.target, record.run_id, &event)?;
    Ok(())
}

pub(crate) fn append_started_trace(record: ToolRunRecord<'_>) -> Result<()> {
    append_run_trace_step_with_next_number(
        record.target,
        record.run_id,
        &RunTraceStep::new(0, "tool", format!("{} started", record.tool))
            .with_tool_name(record.tool),
    )?;
    Ok(())
}

pub(crate) fn append_done_trace(
    record: ToolRunRecord<'_>,
    status: &str,
    cost_usd: Option<f64>,
) -> Result<()> {
    let label = completion_trace_label(record.tool, status);
    if trace_label_exists(record, &label)? {
        return Ok(());
    }
    let mut step = RunTraceStep::new(0, completion_trace_kind(status), label)
        .with_tool_name(record.tool)
        .with_cost_usd(cost_usd);
    if let Some(severity) = completion_trace_severity(status) {
        step = step.with_severity(severity);
    }
    append_run_trace_step_with_next_number(record.target, record.run_id, &step)?;
    Ok(())
}

pub(crate) fn append_failed_trace(record: ToolRunRecord<'_>) -> Result<()> {
    let label = format!("{} failed", record.tool);
    if trace_label_exists(record, &label)? {
        return Ok(());
    }
    append_run_trace_step_with_next_number(
        record.target,
        record.run_id,
        &RunTraceStep::new(0, "refused", label)
            .with_tool_name(record.tool)
            .with_severity("danger"),
    )?;
    Ok(())
}

pub(crate) fn append_recovered_interruption_event(
    target: &Path,
    summary: &RunSummary,
    message: &str,
) -> Result<()> {
    if run_event_exists(target, summary, "interrupted")? {
        return Ok(());
    }
    let mut event = RunEvent::new(0, "run", "interrupted", message);
    if let Some(tool) = summary.tool.as_deref() {
        event = event.with_tool(tool);
    }
    append_run_event(target, &summary.run_id, &event)?;
    Ok(())
}

pub(crate) fn append_recovered_interruption_trace(
    target: &Path,
    summary: &RunSummary,
) -> Result<()> {
    let label = "run interrupted during recovery";
    if run_trace_exists(target, summary, label)? {
        return Ok(());
    }
    let mut step = RunTraceStep::new(0, "refused", label).with_severity("danger");
    if let Some(tool) = summary.tool.as_deref() {
        step = step.with_tool_name(tool);
    }
    append_run_trace_step_with_next_number(target, &summary.run_id, &step)?;
    Ok(())
}

fn trace_label_exists(record: ToolRunRecord<'_>, label: &str) -> Result<bool> {
    Ok(load_run_trace(record.target, record.run_id)?
        .steps
        .into_iter()
        .any(|step| step.label == label && trace_step_matches_tool(&step, record.tool)))
}

fn run_event_exists(target: &Path, summary: &RunSummary, status: &str) -> Result<bool> {
    Ok(load_run_events(target, &summary.run_id)?
        .events
        .into_iter()
        .any(|event| {
            event.kind == "run"
                && event.status == status
                && event.tool.as_deref() == summary.tool.as_deref()
        }))
}

fn run_trace_exists(target: &Path, summary: &RunSummary, label: &str) -> Result<bool> {
    Ok(load_run_trace(target, &summary.run_id)?
        .steps
        .into_iter()
        .any(|step| {
            step.label == label
                && summary
                    .tool
                    .as_deref()
                    .is_none_or(|tool| trace_step_matches_tool(&step, tool))
        }))
}

fn trace_step_matches_tool(step: &RunTraceStep, tool: &str) -> bool {
    let (module_id, verb) = tool.split_once(':').unwrap_or((tool, ""));
    step.module_id.as_deref() == Some(module_id)
        && (verb.is_empty() || step.verb.as_deref() == Some(verb))
}

fn completion_trace_kind(status: &str) -> &'static str {
    match status {
        "failed" => "refused",
        "partial" => "tool-progress",
        _ => "done",
    }
}

fn completion_trace_label(tool: &str, status: &str) -> String {
    match status {
        "completed" => format!("{tool} complete"),
        _ => format!("{tool} {status}"),
    }
}

fn completion_trace_severity(status: &str) -> Option<&'static str> {
    match status {
        "failed" => Some("danger"),
        "partial" => Some("warn"),
        _ => None,
    }
}
