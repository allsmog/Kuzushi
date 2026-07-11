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
    artifacts: &SastRunArtifacts,
    summary_artifact: crate::run_artifacts::RunArtifact,
    result: &Value,
) -> Result<()> {
    let mut recorded_artifacts = vec![summary_artifact];
    recorded_artifacts.extend(record_pipeline_artifacts(workspace, run_id, artifacts)?);
    let seed = load_or_seed_sast_run_summary(workspace, run_id)?;
    let summary = recorded_artifacts.into_iter().fold(
        seed.with_findings(Some(findings_count as u64))
            .with_cost(crate::run_artifacts::tool_run_output_cost_usd(result)),
        crate::run_artifacts::RunSummary::with_artifact,
    );
    crate::run_artifacts::write_run_summary(workspace.root(), &summary)?;
    append_sast_run_started_event_if_empty(workspace, run_id)?;
    append_sast_started_trace_if_empty(workspace, run_id)?;
    crate::run_artifacts::try_record_tool_run_complete(
        crate::run_artifacts::ToolRunRecord::new(workspace.root(), run_id, "scan", "sast:scan"),
        result,
    )?;
    Ok(())
}

fn load_or_seed_sast_run_summary(
    workspace: &WorkspaceTarget,
    run_id: &str,
) -> Result<crate::run_artifacts::RunSummary> {
    let run_id = crate::run_artifacts::RunId::parse(run_id)?;
    let metadata_path =
        crate::run_artifacts::run_dir(workspace.root(), run_id.as_str()).join("run.json");
    match std::fs::symlink_metadata(&metadata_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(crate::run_artifacts::RunSummary::running(
                run_id.as_str().to_string(),
                "scan",
                Some("sast:scan".to_string()),
                workspace.root().display().to_string(),
            ))
        }
        Err(error) => {
            Err(error).with_context(|| format!("Could not inspect {}", metadata_path.display()))
        }
        Ok(_) => crate::run_artifacts::load_run_summary(workspace.root(), run_id.as_str()),
    }
}

fn append_sast_run_started_event_if_empty(workspace: &WorkspaceTarget, run_id: &str) -> Result<()> {
    if crate::run_artifacts::next_run_event_number(workspace.root(), run_id) != 1 {
        return Ok(());
    }
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

fn append_sast_started_trace_if_empty(workspace: &WorkspaceTarget, run_id: &str) -> Result<()> {
    if crate::run_artifacts::next_run_trace_step_number(workspace.root(), run_id) != 1 {
        return Ok(());
    }
    let step = crate::run_artifacts::RunTraceStep::new(0, "tool", "sast:scan started")
        .with_tool_name("sast:scan");
    crate::run_artifacts::append_run_trace_step_with_next_number(workspace.root(), run_id, &step)?;
    Ok(())
}

fn record_pipeline_artifacts(
    workspace: &WorkspaceTarget,
    run_id: &str,
    artifacts: &SastRunArtifacts,
) -> Result<Vec<crate::run_artifacts::RunArtifact>> {
    [
        SAST_SCAN_INPUT_FILE,
        SAST_TRIAGE_JSONL_FILE,
        SAST_VERIFY_JSONL_FILE,
        SAST_PATCH_JSONL_FILE,
    ]
    .into_iter()
    .map(|leaf| {
        let spec = crate::run_artifacts::scan_pipeline_artifact_spec(leaf)
            .context("scan pipeline artifact must be declared")?;
        let body = artifacts.read_text(leaf, spec.label)?;
        crate::run_artifacts::write_run_artifact_text(
            workspace.root(),
            run_id,
            leaf,
            spec.label,
            spec.kind,
            &body,
        )
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record_status(status: &str, ok: bool) -> (crate::run_artifacts::RunSummary, String, String) {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let run_id = format!("scan-{status}");
        let result = json!({
            "ok": ok,
            "status": status,
            "summary": format!("scan {status}"),
            "errors": if status == "completed" { json!([]) } else { json!([format!("scan {status}")]) },
            "data": {"findingsCount": 2}
        });
        let summary_artifact = crate::run_artifacts::write_run_artifact_json(
            workspace.root(),
            &run_id,
            SAST_SUMMARY_FILE,
            "sast summary",
            &result,
        )
        .unwrap();
        let artifacts = SastRunArtifacts::create(&workspace, &run_id).unwrap();
        write_sast_scan_input(&workspace, &run_id, &artifacts, &json!({"runId": run_id})).unwrap();
        write_sast_run_metadata(
            &workspace,
            &run_id,
            2,
            &artifacts,
            summary_artifact,
            &result,
        )
        .unwrap();
        let summary = crate::run_artifacts::load_run_summary(workspace.root(), &run_id).unwrap();
        let events = read_run_text(&workspace, &run_id, "events.jsonl");
        let trace = read_run_text(&workspace, &run_id, "trace.jsonl");
        (summary, events, trace)
    }

    fn read_run_text(workspace: &WorkspaceTarget, run_id: &str, leaf: &str) -> String {
        let path = crate::run_artifacts::run_artifact_path(workspace.root(), run_id, leaf);
        std::fs::read_to_string(path).unwrap()
    }

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

        let artifacts = SastRunArtifacts::create(&workspace, run_id).unwrap();
        write_sast_scan_input(&workspace, run_id, &artifacts, &json!({"runId": run_id})).unwrap();
        write_sast_run_metadata(&workspace, run_id, 2, &artifacts, summary_artifact, &result)
            .unwrap();

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

    #[test]
    fn write_sast_run_metadata_preserves_partial_status() {
        let (summary, events, trace) = record_status("partial", true);

        assert_eq!(summary.status, "partial");
        assert_eq!(summary.error.as_deref(), Some("scan partial"));
        assert_eq!(events.matches("\"status\":\"partial\"").count(), 1);
        assert!(trace.contains("sast:scan partial"), "{trace}");
    }

    #[test]
    fn write_sast_run_metadata_preserves_failed_status() {
        let (summary, events, trace) = record_status("failed", false);

        assert_eq!(summary.status, "failed");
        assert_eq!(summary.error.as_deref(), Some("scan failed"));
        assert_eq!(events.matches("\"status\":\"failed\"").count(), 1);
        assert!(trace.contains("sast:scan failed"), "{trace}");
    }

    #[test]
    fn malformed_existing_run_metadata_is_not_silently_reseeded() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let run_id = "scan-malformed";
        let run_dir = crate::run_artifacts::run_dir(workspace.root(), run_id);
        std::fs::create_dir_all(&run_dir).unwrap();
        let metadata = run_dir.join("run.json");
        std::fs::write(&metadata, "{operator notes").unwrap();

        assert!(load_or_seed_sast_run_summary(&workspace, run_id).is_err());
        assert_eq!(
            std::fs::read_to_string(metadata).unwrap(),
            "{operator notes"
        );
    }
}
