use super::*;

pub(in crate::modules) fn write_sast_summary(
    workspace: &WorkspaceTarget,
    run_id: &str,
    artifacts: &SastRunArtifacts,
    result: &Value,
) -> Result<crate::run_artifacts::RunArtifact> {
    crate::run_artifacts::write_run_artifact_json(
        workspace.root(),
        run_id,
        SAST_SUMMARY_FILE,
        "sast summary",
        result,
    )
    .with_context(|| format!("Could not write {}", artifacts.sast_summary.display()))
}

pub(in crate::modules) fn write_sast_run_metadata(
    workspace: &WorkspaceTarget,
    run_id: &str,
    findings_count: usize,
    summary_artifact: crate::run_artifacts::RunArtifact,
    result: &Value,
) -> Result<()> {
    record_sast_run_events(workspace, run_id, findings_count)?;
    let summary = scan_run_artifacts(workspace, run_id, summary_artifact, result)
        .into_iter()
        .fold(
            crate::run_artifacts::RunSummary::running(
                run_id.to_string(),
                "scan",
                Some("sast:scan".to_string()),
                workspace.root().display().to_string(),
            )
            .complete()
            .with_findings(Some(findings_count as u64))
            .with_loaded_modules(ModuleRegistry::with_v2_builtins().loaded_module_specifiers()),
            crate::run_artifacts::RunSummary::with_artifact,
        );
    crate::run_artifacts::write_run_summary(workspace.root(), &summary)?;
    Ok(())
}

fn record_sast_run_events(
    workspace: &WorkspaceTarget,
    run_id: &str,
    findings_count: usize,
) -> Result<()> {
    append_sast_run_started_event(workspace, run_id)?;
    append_sast_run_completed_event(workspace, run_id, findings_count)?;
    append_sast_run_trace(workspace, run_id, findings_count)?;
    Ok(())
}

fn append_sast_run_started_event(workspace: &WorkspaceTarget, run_id: &str) -> Result<()> {
    let event = crate::run_artifacts::RunEvent::new(
        crate::run_artifacts::next_run_event_number(workspace.root(), run_id),
        "scan",
        "started",
        "sast:scan started",
    )
    .with_tool("sast:scan");
    crate::run_artifacts::append_run_event(workspace.root(), run_id, &event)?;
    Ok(())
}

fn append_sast_run_completed_event(
    workspace: &WorkspaceTarget,
    run_id: &str,
    findings_count: usize,
) -> Result<()> {
    let event = crate::run_artifacts::RunEvent::new(
        crate::run_artifacts::next_run_event_number(workspace.root(), run_id),
        "scan",
        "completed",
        format!("sast:scan completed: {findings_count} finding(s)"),
    )
    .with_tool("sast:scan");
    crate::run_artifacts::append_run_event(workspace.root(), run_id, &event)?;
    Ok(())
}

fn append_sast_run_trace(
    workspace: &WorkspaceTarget,
    run_id: &str,
    findings_count: usize,
) -> Result<()> {
    append_sast_started_trace_if_empty(workspace, run_id)?;
    let step = crate::run_artifacts::RunTraceStep::new(
        0,
        "done",
        format!("sast:scan complete · {findings_count} finding(s)"),
    )
    .with_tool_name("sast:scan");
    crate::run_artifacts::append_run_trace_step_with_next_number(workspace.root(), run_id, &step)?;
    Ok(())
}

fn append_sast_started_trace_if_empty(workspace: &WorkspaceTarget, run_id: &str) -> Result<()> {
    if crate::run_artifacts::next_run_trace_step_number(workspace.root(), run_id) != 1 {
        return Ok(());
    }
    let step = crate::run_artifacts::RunTraceStep::new(0, "tool", "sast:scan started")
        .with_tool_name("sast:scan");
    crate::run_artifacts::append_run_trace_step_with_next_number(workspace.root(), run_id, &step)?;
    Ok(())
}

fn scan_run_artifacts(
    workspace: &WorkspaceTarget,
    run_id: &str,
    summary_artifact: crate::run_artifacts::RunArtifact,
    result: &Value,
) -> Vec<crate::run_artifacts::RunArtifact> {
    let mut artifacts = vec![summary_artifact];
    artifacts.extend(crate::run_artifacts::record_report_artifacts(
        workspace.root(),
        run_id,
        result,
    ));
    artifacts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_sast_run_metadata_records_events_and_trace() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let run_id = "scan-events";
        let result = json!({
            "ok": true,
            "status": "completed",
            "data": {"findingsCount": 2}
        });
        let summary_artifact = crate::run_artifacts::write_run_artifact_json(
            workspace.root(),
            run_id,
            SAST_SUMMARY_FILE,
            "sast summary",
            &result,
        )
        .unwrap();

        write_sast_run_metadata(&workspace, run_id, 2, summary_artifact, &result).unwrap();

        let events = std::fs::read_to_string(crate::run_artifacts::run_artifact_path(
            workspace.root(),
            run_id,
            "events.jsonl",
        ))
        .unwrap();
        let trace = std::fs::read_to_string(crate::run_artifacts::run_artifact_path(
            workspace.root(),
            run_id,
            "trace.jsonl",
        ))
        .unwrap();

        assert!(events.contains("\"status\":\"started\""), "{events}");
        assert!(events.contains("\"status\":\"completed\""), "{events}");
        assert!(trace.contains("sast:scan started"), "{trace}");
        assert!(trace.contains("sast:scan complete"), "{trace}");
    }
}
