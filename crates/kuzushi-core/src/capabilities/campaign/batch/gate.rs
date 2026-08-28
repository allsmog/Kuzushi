use super::super::campaign_dir;
use crate::findings::Severity;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const SCAN_BATCH_GATE_FILE: &str = "gate.json";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScanBatchGatePolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fail_on: Option<Severity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sarif: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BatchGateStatus {
    Disabled,
    Passed,
    Failed,
    Incomplete,
}

impl BatchGateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Incomplete => "incomplete",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BatchOperationalStatus {
    Complete,
    Incomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BatchSecurityGateStatus {
    Disabled,
    Passed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScanBatchGateBinding {
    pub logical_terminal_state_sha256: String,
    pub blocking_findings_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sarif_path: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sarif_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScanBatchGateOutcome {
    pub schema_version: u32,
    pub batch_id: String,
    pub equivalence_key: String,
    pub policy: ScanBatchGatePolicy,
    pub status: BatchGateStatus,
    pub operational_status: BatchOperationalStatus,
    pub security_status: BatchSecurityGateStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold: Option<Severity>,
    pub planned_trials: usize,
    pub completed_trials: usize,
    pub failed_trials: usize,
    pub pending_trials: usize,
    pub completed_run_ids: Vec<String>,
    pub blocking_safe_fold_count: usize,
    pub sarif_written: bool,
    pub binding: ScanBatchGateBinding,
    pub recorded_at_ms: u64,
}

impl ScanBatchGateOutcome {
    pub fn new(
        batch_id: impl Into<String>,
        equivalence_key: impl Into<String>,
        policy: &ScanBatchGatePolicy,
        counts: ScanBatchGateCounts,
        binding: ScanBatchGateBinding,
    ) -> Self {
        let operational_status = operational_status(&counts);
        let security_status = security_status(policy.fail_on, counts.blocking_safe_fold_count);
        Self {
            schema_version: 1,
            batch_id: batch_id.into(),
            equivalence_key: equivalence_key.into(),
            policy: policy.clone(),
            status: gate_status(operational_status, security_status),
            operational_status,
            security_status,
            threshold: policy.fail_on,
            planned_trials: counts.planned_trials,
            completed_trials: counts.completed_trials,
            failed_trials: counts.failed_trials,
            pending_trials: counts.pending_trials,
            completed_run_ids: counts.completed_run_ids,
            blocking_safe_fold_count: counts.blocking_safe_fold_count,
            sarif_written: counts.sarif_written,
            binding,
            recorded_at_ms: epoch_ms(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.schema_version == 1,
            "unsupported batch gate schema version"
        );
        anyhow::ensure!(
            !self.equivalence_key.is_empty(),
            "batch gate is missing equivalenceKey"
        );
        anyhow::ensure!(
            self.threshold == self.policy.fail_on,
            "batch gate threshold disagrees with its policy"
        );
        anyhow::ensure!(
            self.completed_trials + self.failed_trials + self.pending_trials == self.planned_trials,
            "batch gate logical-trial counts do not sum to plannedTrials"
        );
        let operational = operational_status(&self.counts());
        let security = security_status(self.policy.fail_on, self.blocking_safe_fold_count);
        anyhow::ensure!(
            self.operational_status == operational
                && self.security_status == security
                && self.status == gate_status(operational, security),
            "batch gate status disagrees with its policy/logical-trial counts"
        );
        anyhow::ensure!(
            !self.sarif_written || self.policy.sarif.is_some(),
            "batch gate records SARIF outside its policy"
        );
        self.binding.validate(self.sarif_written)?;
        Ok(())
    }

    fn counts(&self) -> ScanBatchGateCounts {
        ScanBatchGateCounts {
            planned_trials: self.planned_trials,
            completed_trials: self.completed_trials,
            failed_trials: self.failed_trials,
            pending_trials: self.pending_trials,
            completed_run_ids: self.completed_run_ids.clone(),
            blocking_safe_fold_count: self.blocking_safe_fold_count,
            sarif_written: self.sarif_written,
        }
    }
}

impl ScanBatchGateBinding {
    fn validate(&self, sarif_written: bool) -> Result<()> {
        anyhow::ensure!(
            !self.logical_terminal_state_sha256.is_empty()
                && !self.blocking_findings_sha256.is_empty(),
            "batch gate is missing state/finding bindings"
        );
        anyhow::ensure!(
            sarif_written == self.sarif_sha256.is_some()
                && self.sarif_path.is_some() == self.sarif_sha256.is_some(),
            "batch gate SARIF digest disagrees with sarifWritten"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanBatchGateCounts {
    pub planned_trials: usize,
    pub completed_trials: usize,
    pub failed_trials: usize,
    pub pending_trials: usize,
    pub completed_run_ids: Vec<String>,
    pub blocking_safe_fold_count: usize,
    pub sarif_written: bool,
}

pub fn persist_batch_gate_outcome(root: &Path, outcome: &ScanBatchGateOutcome) -> Result<PathBuf> {
    outcome.validate()?;
    let path = campaign_dir(root, &outcome.batch_id).join(SCAN_BATCH_GATE_FILE);
    let body = serde_json::to_string_pretty(outcome).context("could not serialize batch gate")?;
    crate::fs_atomic::write_atomic(&path, &body)
        .with_context(|| format!("could not persist batch gate at {}", path.display()))?;
    Ok(path)
}

pub fn persist_batch_sarif_document(path: &Path, document: &serde_json::Value) -> Result<String> {
    let body = serde_json::to_vec_pretty(document).context("could not serialize batch SARIF")?;
    crate::fs_atomic::write_atomic_bytes(path, &body)
        .with_context(|| format!("could not publish batch SARIF at {}", path.display()))?;
    Ok(crate::run_lifecycle::sha256_content_digest(&body))
}

fn operational_status(counts: &ScanBatchGateCounts) -> BatchOperationalStatus {
    if counts.completed_trials == counts.planned_trials
        && counts.failed_trials == 0
        && counts.pending_trials == 0
    {
        BatchOperationalStatus::Complete
    } else {
        BatchOperationalStatus::Incomplete
    }
}

fn security_status(threshold: Option<Severity>, blocking: usize) -> BatchSecurityGateStatus {
    match (threshold, blocking) {
        (None, _) => BatchSecurityGateStatus::Disabled,
        (Some(_), 0) => BatchSecurityGateStatus::Passed,
        (Some(_), _) => BatchSecurityGateStatus::Failed,
    }
}

fn gate_status(
    operational: BatchOperationalStatus,
    security: BatchSecurityGateStatus,
) -> BatchGateStatus {
    if operational == BatchOperationalStatus::Incomplete {
        return BatchGateStatus::Incomplete;
    }
    match security {
        BatchSecurityGateStatus::Disabled => BatchGateStatus::Disabled,
        BatchSecurityGateStatus::Passed => BatchGateStatus::Passed,
        BatchSecurityGateStatus::Failed => BatchGateStatus::Failed,
    }
}

fn epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests;
