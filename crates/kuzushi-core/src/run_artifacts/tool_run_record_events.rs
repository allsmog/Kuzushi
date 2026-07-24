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
