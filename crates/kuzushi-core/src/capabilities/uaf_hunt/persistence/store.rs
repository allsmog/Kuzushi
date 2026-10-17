use crate::capabilities::uaf_hunt::domain::UafHuntPersistedRun;
use crate::findings::Finding;
use crate::modules::ToolExecutionContext;
use crate::runtime::LoopHistoryEntry;
use anyhow::{Context, Result};
use std::path::Path;

#[cfg(test)]
pub fn persist_uaf_hunt_findings(
    target: &Path,
    findings: &[Finding],
    transcript: &[LoopHistoryEntry],
    ctx: &ToolExecutionContext<'_>,
) -> Result<Option<UafHuntPersistedRun>> {
    persist_uaf_hunt_outcome(
        target,
        findings,
        transcript,
        crate::run_lifecycle::RunItemStatus::Completed,
        ctx,
    )
}

pub(crate) fn persist_uaf_hunt_outcome(
    target: &Path,
    findings: &[Finding],
    transcript: &[LoopHistoryEntry],
    status: crate::run_lifecycle::RunItemStatus,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Option<UafHuntPersistedRun>> {
    let (Some(workspace), Some(store)) = (ctx.workspace, ctx.findings_store) else {
        return Ok(None);
    };
    workspace.ensure_state_dir()?;
    let run_id = ctx.finding_run_id();
    if !transcript.is_empty() {
        crate::workspace::prepare_workspace_output_path(
            workspace.root(),
            transcript_relative_path(&run_id),
        )?;
    }
    persist_uaf_findings_run(&run_id, target, findings, status, store)?;
    let transcript_path = write_uaf_hunt_transcript(workspace.root(), &run_id, transcript)?;

    Ok(Some(UafHuntPersistedRun {
        run_id,
        findings_db: workspace.findings_db_path().display().to_string(),
        transcript_path,
    }))
}

fn persist_uaf_findings_run(
    run_id: &str,
    target: &Path,
    findings: &[Finding],
    status: crate::run_lifecycle::RunItemStatus,
    store: &crate::findings::FindingStore,
) -> Result<()> {
    store.with_run_lifecycle_status(run_id, target, || {
        insert_uaf_findings(run_id, findings, store)?;
        Ok(((), findings.len(), status))
    })?;
    Ok(())
}

fn insert_uaf_findings(
    run_id: &str,
    findings: &[Finding],
    store: &crate::findings::FindingStore,
) -> Result<()> {
    for finding in findings {
        store.insert_finding(run_id, finding)?;
    }
    Ok(())
}

/// Write each `LoopHistoryEntry` as a single JSON line to
/// `<state>/uaf-hunt-runs/<run_id>/transcript.jsonl`. The directory is
/// inside the workspace state dir (next to index.sqlite3) rather than
/// the CLI's `.kuzushi/v3/runs/<run-id>` tree so the transcript survives
/// independently of how the tool was launched (CLI, TUI, scan worker).
fn write_uaf_hunt_transcript(
    workspace_root: &Path,
    run_id: &str,
    transcript: &[LoopHistoryEntry],
) -> Result<Option<String>> {
    if transcript.is_empty() {
        return Ok(None);
    }
    let relative = transcript_relative_path(run_id);
    let mut body = Vec::new();
    let max_bytes = usize::try_from(crate::run_artifacts::MAX_RUN_ARTIFACT_READ_BYTES)
        .context("run artifact byte limit does not fit this platform")?;
    for entry in transcript {
        let line = serde_json::to_string(entry).context("uaf-hunt: serialise transcript entry")?;
        anyhow::ensure!(
            body.len().saturating_add(line.len()).saturating_add(1) <= max_bytes,
            "uaf-hunt transcript exceeds {} bytes",
            crate::run_artifacts::MAX_RUN_ARTIFACT_READ_BYTES
        );
        body.extend_from_slice(line.as_bytes());
        body.push(b'\n');
    }
    let path = crate::workspace::write_workspace_state_file(workspace_root, relative, &body)
        .context("uaf-hunt: could not persist transcript")?;
    Ok(Some(path.display().to_string()))
}

fn transcript_relative_path(run_id: &str) -> std::path::PathBuf {
    Path::new(".kuzushi/v3/uaf-hunt-runs")
        .join(run_id)
        .join("transcript.jsonl")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::V2Config;
    use crate::findings::{FindingStore, Severity};
    use crate::run_artifacts::TraceHandle;
    use crate::runtime::{ToolCall, ToolResult};
    use crate::workspace::WorkspaceTarget;

    #[test]
    fn persistence_uses_the_canonical_trace_run_id() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let config = V2Config::default();
        let trace = TraceHandle::jsonl(temp.path(), "run-uaf-canonical");
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: Some(&trace),
            cancellation: None,
            authorization: Default::default(),
        };
        let finding = Finding::new_tool(
            "uaf-hunt",
            "CWE-416",
            "src/lib.c",
            7,
            None,
            Severity::High,
            "use after free",
        );

        let persisted = persist_uaf_hunt_findings(temp.path(), &[finding], &[], &ctx)
            .unwrap()
            .unwrap();

        assert_eq!(persisted.run_id, "run-uaf-canonical");
        let findings = store
            .list_findings_for_scan_id("run-uaf-canonical")
            .unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].scan_id.as_deref(), Some("run-uaf-canonical"));
    }

    #[test]
    fn transcript_writer_skips_empty_and_writes_jsonl() {
        let temp = tempfile::tempdir().unwrap();
        assert!(write_uaf_hunt_transcript(temp.path(), "run-empty", &[])
            .unwrap()
            .is_none());

        let transcript = vec![
            LoopHistoryEntry::AssistantToolCall(ToolCall {
                name: "grep".to_string(),
                input: serde_json::json!({"pattern": "free"}),
                call_id: "call-1".to_string(),
            }),
            LoopHistoryEntry::ToolResult(ToolResult {
                call_id: "call-1".to_string(),
                output: serde_json::json!({"matches": []}),
                is_error: false,
            }),
        ];

        let path = write_uaf_hunt_transcript(temp.path(), "run-1", &transcript)
            .unwrap()
            .expect("transcript path");
        let raw = std::fs::read_to_string(path).unwrap();

        assert_eq!(raw.lines().count(), 2);
        assert!(raw.contains("\"grep\""));
        assert!(raw.contains("\"matches\""));
    }

    #[cfg(unix)]
    #[test]
    fn transcript_writer_rejects_symlinked_state_parent() {
        use std::os::unix::fs::symlink;

        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(workspace.path().join(".kuzushi/v3")).unwrap();
        symlink(
            outside.path(),
            workspace.path().join(".kuzushi/v3/uaf-hunt-runs"),
        )
        .unwrap();
        let transcript = vec![LoopHistoryEntry::ToolResult(ToolResult {
            call_id: "call-1".to_string(),
            output: serde_json::json!({"safe": true}),
            is_error: false,
        })];

        assert!(write_uaf_hunt_transcript(workspace.path(), "run-1", &transcript).is_err());
        assert!(std::fs::read_dir(outside.path()).unwrap().next().is_none());
    }
}
