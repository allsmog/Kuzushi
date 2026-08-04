use super::*;
use std::collections::BTreeMap;

/// Tool-generic per-run stage receipts (`<run>/stages.jsonl`), the durable
/// audit sibling of the sast:scan-specific `phase-stages.jsonl`. Any
/// multi-stage tool appends one receipt per finished stage; the
/// stage-checkpoint store mirrors `Completed` receipts across runs so a
/// failed run's paid stages survive into its continuation run.
pub const TOOL_STAGES_JSONL_FILE: &str = "stages.jsonl";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolStageReceipt {
    /// Stable stage id, e.g. "research", "actor:remote_unauth", "engine:semgrep".
    pub stage: String,
    pub outcome: PhaseStageOutcome,
    /// Target-relative paths this stage wrote. A continuation trusts a
    /// completed stage only when every path still exists and its digest still
    /// matches the content committed by the completing run.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<String>,
    /// Content digest keyed by the exact target-relative artifact path. Empty
    /// on legacy receipts and skipped stages; a completed stage with artifacts
    /// but no complete digest set is deliberately not reusable.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub artifact_digests: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub recorded_at_ms: u64,
}

/// Append one stage receipt to the run's `stages.jsonl`. Best-effort at the
/// caller: a failed receipt write must never fail the paid run it audits.
pub fn append_tool_stage_receipt(
    target: &Path,
    run_id: &str,
    receipt: &ToolStageReceipt,
) -> Result<()> {
    let path = append_run_artifact_jsonl_value(
        target,
        run_id,
        TOOL_STAGES_JSONL_FILE,
        &serde_json::to_value(receipt)?,
    )?;
    let _ = record_run_artifact(target, run_id, &stage_receipts_artifact(&path));
    Ok(())
}

fn stage_receipts_artifact(path: &Path) -> RunArtifact {
    let spec = crate::artifact_contract::optional_run_artifact_spec(TOOL_STAGES_JSONL_FILE)
        .expect("tool stage receipts must be in shared spec");
    RunArtifact {
        label: spec.label.to_string(),
        path: path.display().to_string(),
        kind: spec.kind.to_string(),
    }
}

/// All stage receipts recorded by a run, in append order. Missing file is
/// an empty list, not an error — most tools never write stage receipts.
pub fn load_tool_stage_receipts(
    target: impl AsRef<Path>,
    run_id: &str,
) -> Result<Vec<ToolStageReceipt>> {
    let read = read_run_artifact_text(target, run_id, TOOL_STAGES_JSONL_FILE);
    let body = match read {
        RunArtifactRead::Ready { value, .. } => value,
        RunArtifactRead::Missing { .. } => return Ok(Vec::new()),
        other => return other.require("Tool stage receipts").map(|_| Vec::new()),
    };
    body.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str::<ToolStageReceipt>(line).context("invalid tool stage receipt")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_receipts_append_and_load_in_order() {
        let temp = tempfile::tempdir().unwrap();
        let receipt = |stage: &str| ToolStageReceipt {
            stage: stage.to_string(),
            outcome: PhaseStageOutcome::Completed,
            artifacts: vec![format!(".kuzushi/tm/{stage}.json")],
            artifact_digests: BTreeMap::new(),
            detail: None,
            recorded_at_ms: 7,
        };
        append_tool_stage_receipt(temp.path(), "run-stages", &receipt("research")).unwrap();
        append_tool_stage_receipt(temp.path(), "run-stages", &receipt("coverage")).unwrap();

        let loaded = load_tool_stage_receipts(temp.path(), "run-stages").unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].stage, "research");
        assert_eq!(loaded[1].stage, "coverage");

        let manifest = crate::run_artifacts::load_run_artifacts(temp.path(), "run-stages").unwrap();
        assert!(manifest.iter().any(|artifact| {
            artifact.path.ends_with("stages.jsonl")
                && artifact.label == "tool stage receipts"
                && artifact.kind == "jsonl"
        }));
    }

    #[test]
    fn legacy_receipt_without_digests_still_deserializes() {
        let receipt: ToolStageReceipt = serde_json::from_value(serde_json::json!({
            "stage": "research",
            "outcome": "completed",
            "artifacts": ["research.json"],
            "recordedAtMs": 7
        }))
        .unwrap();

        assert!(receipt.artifact_digests.is_empty());
    }

    #[test]
    fn missing_stage_receipts_file_is_an_empty_list() {
        let temp = tempfile::tempdir().unwrap();
        assert!(load_tool_stage_receipts(temp.path(), "run-none")
            .unwrap()
            .is_empty());
    }
}
