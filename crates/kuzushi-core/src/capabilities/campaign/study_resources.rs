//! Historical usage for plan review, never a price or execution guarantee.
use super::*;
use crate::{allowance::ProviderRunUsage, run_artifacts::RunSummary};
use serde::{Deserialize, Serialize};
pub(super) mod campaign_baseline;
pub(super) mod campaign_preview;
pub(super) mod catalogue;
pub(super) mod study_catalogue;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanResourceEvidence {
    pub run_id: String,
    pub cost_usd: Option<f64>,
    pub provider_usage: Option<ProviderRunUsage>,
    pub equivalence: Option<BatchEquivalenceKey>,
    pub calibration_limitation: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct StudyResourceProjection {
    pub provider_calls: Option<u64>,
    pub cost_usd: Option<f64>,
    pub starts: u64,
}

impl ScanResourceEvidence {
    pub fn project(
        &self,
        expected: &BatchEquivalenceKey,
        trials: usize,
        attempts: usize,
    ) -> Result<StudyResourceProjection> {
        anyhow::ensure!(
            (1..=100).contains(&trials) && (1..=10).contains(&attempts),
            "invalid projected workload"
        );
        anyhow::ensure!(
            self.calibration_limitation.is_none(),
            "{}",
            self.calibration_limitation.as_deref().unwrap_or_default()
        );
        let baseline = self
            .equivalence
            .as_ref()
            .context("historical scan conditions unavailable")?;
        anyhow::ensure!(
            baseline == expected,
            "historical source, context, scan options, model or runtime conditions differ"
        );
        let calls = self.settled_provider_calls()?;
        let starts = (trials as u64)
            .checked_mul(attempts as u64)
            .context("projection overflow")?;
        let provider_calls = calls.map(|calls| u64::from(calls) * starts);
        let cost_usd = self
            .cost_usd
            .map(|cost| cost * starts as f64)
            .filter(|cost| cost.is_finite());
        Ok(StudyResourceProjection {
            provider_calls,
            cost_usd,
            starts,
        })
    }

    fn settled_provider_calls(&self) -> Result<Option<u32>> {
        let Some(usage) = &self.provider_usage else {
            return Ok(None);
        };
        anyhow::ensure!(
            usage.unresolved_calls == 0,
            "historical requests remain unresolved"
        );
        Ok(Some(usage.committed_calls))
    }
}

/// Read one completed SAST run. Missing legacy accounting stays unknown.
pub fn load_scan_resource_evidence(
    root: &Path,
    summary: &RunSummary,
) -> Result<ScanResourceEvidence> {
    anyhow::ensure!(
        summary.status == "completed" && summary.tool.as_deref() == Some("sast:scan"),
        "usage calibration requires a completed discovery scan"
    );
    let db = crate::WorkspaceTarget::new(root)?.findings_db_path();
    let usage = crate::SpendLimiter::read_run_provider_usage(&db, &summary.run_id)?;
    let equivalent = read_equivalence(root, &summary.run_id)?;
    validate_usage_identity(usage.as_ref(), equivalent.as_ref())?;
    Ok(ScanResourceEvidence {
        run_id: summary.run_id.clone(),
        cost_usd: (!summary.provider_spend_unresolved)
            .then_some(summary.cost_usd)
            .flatten()
            .filter(|cost| cost.is_finite() && *cost >= 0.0),
        provider_usage: usage,
        equivalence: equivalent,
        calibration_limitation: completion_limitation(root, &summary.run_id)?,
    })
}

fn completion_limitation(root: &Path, run: &str) -> Result<Option<String>> {
    use crate::run_artifacts::{load_scan_stage_data, PhaseStageOutcome};
    let Some(receipt) = load_scan_stage_data(root, run)? else {
        return Ok(Some(
            "historical scan has no per-engine completion receipt".into(),
        ));
    };
    let complete = (receipt.phase, receipt.outcome)
        == (crate::WorkflowPhase::Scan, PhaseStageOutcome::Completed)
        && receipt.scan.as_ref().is_some_and(engines_complete);
    Ok((!complete).then(|| "historical scan has partial, skipped or failed engine work".into()))
}

fn engines_complete(scan: &crate::run_artifacts::ScanStageData) -> bool {
    use crate::run_artifacts::ScanEngineStageOutcome;
    !scan.engines.is_empty()
        && scan
            .engines
            .iter()
            .all(|engine| engine.outcome == ScanEngineStageOutcome::Complete)
}

fn read_equivalence(root: &Path, run: &str) -> Result<Option<BatchEquivalenceKey>> {
    use crate::run_artifacts::RunArtifactRead;
    match crate::run_artifacts::read_run_artifact_text(
        root,
        run,
        SCAN_BATCH_EQUIVALENCE_RECEIPT_FILE,
    ) {
        RunArtifactRead::Missing { .. } => Ok(None),
        RunArtifactRead::Ready { value, .. } => {
            let receipt: ScanBatchChildEquivalenceReceipt = serde_json::from_str(&value)?;
            receipt.validate()?;
            Ok(Some(receipt.consumed))
        }
        other => other.require("historical scan conditions").map(|_| None),
    }
}

fn validate_usage_identity(
    usage: Option<&ProviderRunUsage>,
    equivalent: Option<&BatchEquivalenceKey>,
) -> Result<()> {
    let Some(usage) = usage else {
        return Ok(());
    };
    anyhow::ensure!(
        usage.tool == "sast:scan",
        "request evidence belongs to another tool"
    );
    let Some(key) = equivalent else {
        return Ok(());
    };
    let source = &key.components;
    anyhow::ensure!(
        usage.source_identity == source.workspace_identity
            && usage.config_sha256 == source.config_sha256,
        "request evidence and recorded scan conditions differ"
    );
    if usage.committed_calls > 0 {
        anyhow::ensure!(
            source.model.as_deref() == Some(usage.model.as_str()),
            "request evidence has a different scan model"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests;
