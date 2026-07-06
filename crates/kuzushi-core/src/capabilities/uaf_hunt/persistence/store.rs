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
    let run_id = persist_uaf_findings_run(target, findings, store)?;
    let transcript_path = write_uaf_hunt_transcript(&workspace.state_dir(), &run_id, transcript)?;

    Ok(Some(UafHuntPersistedRun {
        run_id,
        findings_db: workspace.findings_db_path().display().to_string(),
        transcript_path,
    }))
}

fn persist_uaf_findings_run(
    target: &Path,
    findings: &[Finding],
    store: &crate::findings::FindingStore,
) -> Result<String> {
    let run_id = Uuid::new_v4().to_string();
    start_uaf_findings_run(&run_id, target, findings, store)?;
    complete_uaf_findings_run(&run_id, findings.len(), store)?;
    Ok(run_id)
}

fn start_uaf_findings_run(
    run_id: &str,
    target: &Path,
    findings: &[Finding],
    store: &crate::findings::FindingStore,
) -> Result<()> {
    store.record_run_started(run_id, target, "running")?;
    insert_uaf_findings(run_id, findings, store)
}

fn complete_uaf_findings_run(
    run_id: &str,
    finding_count: usize,
    store: &crate::findings::FindingStore,
) -> Result<()> {
    store.record_run_finished(run_id, "completed", finding_count)
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
        let line = serde_json::to_string(entry).context("uaf-hunt: serialise transcript entry")?;
        writeln!(file, "{line}")
            .with_context(|| format!("uaf-hunt: could not write {}", path.display()))?;
    }
    Ok(Some(path.display().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{ToolCall, ToolResult};

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
}
