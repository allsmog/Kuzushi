use super::*;
use crate::workflow_attempts::PhaseTargetSnapshot;
use crate::WorkflowPhase;

pub const SAST_PHASE_STAGES_JSONL_FILE: &str = "phase-stages.jsonl";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PhaseStageOutcome {
    Completed,
    Partial,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanEngineStageOutcome {
    Complete,
    Partial,
    Skipped,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScanStageScope {
    pub target: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScanStagePlan {
    pub selection: String,
    pub engines: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScanStageEngine {
    pub engine: String,
    pub outcome: ScanEngineStageOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScanFindingDelta {
    pub added: u64,
    pub updated: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScanSeverityCount {
    pub severity: crate::findings::Severity,
    pub count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScanArtifactDelta {
    pub run_ref: String,
    pub path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScanStageCost {
    pub observed_usd: f64,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScanStageData {
    pub scope: ScanStageScope,
    pub plan: ScanStagePlan,
    pub engines: Vec<ScanStageEngine>,
    pub finding_delta: ScanFindingDelta,
    /// Findings this attempt produced, bucketed by severity, highest band
    /// first. Empty when the attempt found nothing or the receipt predates
    /// severity recording — the cockpit renders no chips rather than zeros.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub severity_counts: Vec<ScanSeverityCount>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifact_delta: Vec<ScanArtifactDelta>,
    pub duration_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost: Option<ScanStageCost>,
    pub target_snapshot: PhaseTargetSnapshot,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PhaseStageReceipt {
    pub phase: WorkflowPhase,
    pub outcome: PhaseStageOutcome,
    pub run_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan: Option<ScanStageData>,
}

/// Loads the typed durable Scan payload from a SAST parent run. Legacy phase
/// rows deserialize with `scan: None` and remain available to legacy summary
/// projection without inventing per-engine or delta data.
pub fn load_scan_stage_data(
    target: impl AsRef<Path>,
    run_id: &str,
) -> Result<Option<PhaseStageReceipt>> {
    if let result_receipt::ScanReceiptSource::Typed(receipt) =
        result_receipt::load(target.as_ref(), run_id)?
    {
        return Ok(receipt);
    }
    let read = read_run_artifact_text(target, run_id, SAST_PHASE_STAGES_JSONL_FILE);
    let (_, body) = match read {
        RunArtifactRead::Ready { path, value } => (path, value),
        RunArtifactRead::Missing { .. } => return Ok(None),
        other => return other.require("Scan stage receipt").map(|_| None),
    };
    let receipts = body
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str::<PhaseStageReceipt>(line)
                .context("invalid SAST phase stage receipt")
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(receipts
        .into_iter()
        .rev()
        .find(|receipt| receipt.phase == WorkflowPhase::Scan && receipt.scan.is_some()))
}

/// Include engine observation runs while keeping the accepted parent runs intact.
/// This reads one level of recorded receipt membership and starts no work.
pub fn scan_finding_run_refs(target: &Path, parent_runs: &[String]) -> Result<Vec<String>> {
    let mut runs = parent_runs
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    for parent in parent_runs {
        if let Some(receipt) = load_scan_stage_data(target, parent)? {
            for run in &receipt.run_refs {
                crate::RunId::parse(run).context("invalid Scan observation run reference")?;
            }
            runs.extend(receipt.run_refs);
        }
    }
    Ok(runs.into_iter().collect())
}

mod result_receipt;

mod scope;
pub(crate) use scope::scan_paths_cover_file;
