use super::tool_run_record::ToolRunRecord;
use super::*;

pub(crate) fn append_started_event(record: ToolRunRecord<'_>, artifact: Option<RunArtifact>) {
    let mut event = RunEvent::new(
        next_run_event_number(record.target, record.run_id),
        "tool",
        "started",
        format!("{} started", record.tool),
    )
    .with_tool(record.tool);
    if let Some(artifact) = artifact {
        event = event.with_artifact(artifact);
    }
    let _ = append_run_event(record.target, record.run_id, &event);
}

pub(crate) fn append_tool_event(record: ToolRunRecord<'_>, status: &str, message: &str) {
    let event = RunEvent::new(
        next_run_event_number(record.target, record.run_id),
        "tool",
        status,
        message,
    )
    .with_tool(record.tool);
    let _ = append_run_event(record.target, record.run_id, &event);
}

pub(crate) fn append_started_trace(record: ToolRunRecord<'_>) {
    let _ = append_run_trace_step_with_next_number(
        record.target,
        record.run_id,
        &RunTraceStep::new(0, "tool", format!("{} started", record.tool))
            .with_tool_name(record.tool),
    );
}

pub(crate) fn append_done_trace(
    record: ToolRunRecord<'_>,
    status: &str,
    cost_usd: Option<f64>,
) {
    let mut step = RunTraceStep::new(
        0,
        completion_trace_kind(status),
        completion_trace_label(record.tool, status),
    )
    .with_tool_name(record.tool)
    .with_cost_usd(cost_usd);
    if let Some(severity) = completion_trace_severity(status) {
        step = step.with_severity(severity);
    }
    let _ = append_run_trace_step_with_next_number(record.target, record.run_id, &step);
}

pub(crate) fn append_failed_trace(record: ToolRunRecord<'_>) {
    let _ = append_run_trace_step_with_next_number(
        record.target,
        record.run_id,
        &RunTraceStep::new(
            0,
            "refused",
            format!("{} failed", record.tool),
        )
        .with_tool_name(record.tool)
        .with_severity("danger"),
    );
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
