use crate::capabilities::uaf_hunt::domain::UafHuntPersistedRun;
use crate::findings::Finding;
use crate::modules::ToolExecutionContext;
use crate::runtime::LoopHistoryEntry;
use anyhow::{Context, Result};
use std::fs;
use std::io::Write;
use std::path::Path;
use uuid::Uuid;

pub fn persist_uaf_hunt_findings(
    target: &Path,
    findings: &[Finding],
    transcript: &[LoopHistoryEntry],
    ctx: &ToolExecutionContext<'_>,
) -> Result<Option<UafHuntPersistedRun>> {
    let (Some(workspace), Some(store)) = (ctx.workspace, ctx.findings_store) else {
        return Ok(None);
    };
    workspace.ensure_state_dir()?;
    let run_id = Uuid::new_v4().to_string();
    store.insert_scan_run(&run_id, target, "running")?;
    for finding in findings {
        store.insert_finding(&run_id, finding)?;
    }
    store.complete_scan_run(&run_id, "completed", findings.len())?;
    let transcript_path = write_uaf_hunt_transcript(&workspace.state_dir(), &run_id, transcript)?;

    Ok(Some(UafHuntPersistedRun {
        run_id,
        findings_db: workspace.findings_db_path().display().to_string(),
        transcript_path,
    }))
}

/// Write each `LoopHistoryEntry` as a single JSON line to
/// `<state>/uaf-hunt-runs/<run_id>/transcript.jsonl`. The directory is
/// inside the workspace state dir (next to findings.sqlite3) rather than
/// the CLI's `.kuzushi/runs/<run-id>` tree so the transcript survives
/// independently of how the tool was launched (CLI, TUI, scan worker).
fn write_uaf_hunt_transcript(
    state_dir: &Path,
    run_id: &str,
    transcript: &[LoopHistoryEntry],
) -> Result<Option<String>> {
    if transcript.is_empty() {
        return Ok(None);
    }
    let dir = state_dir.join("uaf-hunt-runs").join(run_id);
    fs::create_dir_all(&dir)
        .with_context(|| format!("uaf-hunt: could not create {}", dir.display()))?;
    let path = dir.join("transcript.jsonl");
    let mut file = fs::File::create(&path)
        .with_context(|| format!("uaf-hunt: could not create {}", path.display()))?;
    for entry in transcript {
        let line = serde_json::to_string(entry)
            .context("uaf-hunt: serialise transcript entry")?;
        writeln!(file, "{line}")
            .with_context(|| format!("uaf-hunt: could not write {}", path.display()))?;
    }
    Ok(Some(path.display().to_string()))
}
