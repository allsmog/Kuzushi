use crate::findings::{
    PersistedProofVerdict, PersistedSandboxBackend, PersistedVerification, VerificationProvenance,
};
use crate::run_artifacts::{tool_run_output_cost_report, RunSummary};
use crate::runtime::RuntimeCostReport;
use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ModelProofCandidate {
    pub(super) fingerprint: String,
    pub(super) verified_scan_id: String,
    pub(super) identity_id: Option<String>,
    pub(super) source_identity: crate::workflow_attempts::TargetContentIdentity,
    exploitable: bool,
    confidence: f64,
    proof_level: u8,
    proof_verdict: PersistedProofVerdict,
}

impl ModelProofCandidate {
    pub(super) fn from_result(result: &Value) -> Result<Self> {
        anyhow::ensure!(
            result.get("ok").and_then(Value::as_bool) == Some(true),
            "proof result is not successful"
        );
        anyhow::ensure!(
            result.get("status").and_then(Value::as_str) == Some("completed"),
            "proof result is not completed"
        );
        let data = parse_candidate(result.get("data"), "proof result data")?;
        let nested = parse_candidate(
            result.pointer("/data/verification"),
            "verification candidate",
        )?;
        let nested_proof = parse_candidate(result.pointer("/data/proof"), "nested proof snapshot")?;
        let proof = parse_candidate(result.get("proof"), "proof snapshot")?;
        anyhow::ensure!(
            data == nested && nested == nested_proof && nested_proof == proof,
            "proof result contains conflicting candidate identities or verdicts"
        );
        data.validate()?;
        Ok(data)
    }

    fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            !self.fingerprint.trim().is_empty(),
            "proof fingerprint is empty"
        );
        anyhow::ensure!(
            !self.verified_scan_id.trim().is_empty(),
            "proof discovery run id is empty"
        );
        anyhow::ensure!(
            (1..=3).contains(&self.proof_level),
            "static model proof level is outside 1..=3"
        );
        anyhow::ensure!(
            self.confidence.is_finite() && (0.0..=1.0).contains(&self.confidence),
            "proof confidence is outside 0..=1"
        );
        VerificationProvenance {
            source_identity: self.source_identity.clone(),
            reproducer: None,
        }
        .validate()
        .context("proof source identity is invalid")?;
        let expected = if self.exploitable {
            PersistedProofVerdict::Exploited
        } else {
            PersistedProofVerdict::NotReproduced
        };
        anyhow::ensure!(
            self.proof_verdict == expected,
            "proof verdict contradicts exploitability"
        );
        Ok(())
    }

    pub(super) fn validate_current_source(&self, target: &std::path::Path) -> Result<()> {
        let expected = match &self.source_identity {
            crate::workflow_attempts::TargetContentIdentity::IndexedSnapshot {
                tree_hash: Some(tree_hash),
                ..
            } => tree_hash.as_str(),
            crate::workflow_attempts::TargetContentIdentity::IndexedSnapshot {
                tree_hash: None,
                ..
            } => anyhow::bail!("proof source identity has no workspace tree hash"),
            crate::workflow_attempts::TargetContentIdentity::CleanGitCommit { .. } => {
                anyhow::bail!("model proof source identity is not an indexed workspace snapshot")
            }
            crate::workflow_attempts::TargetContentIdentity::Unavailable { reason } => {
                anyhow::bail!("model proof source identity is unavailable: {reason}")
            }
        };
        let current = crate::incremental_index::current_workspace_tree_hash(target)
            .context("could not verify the current model-proof source identity")?;
        anyhow::ensure!(
            current == expected,
            "model proof source identity is stale for the current workspace"
        );
        Ok(())
    }

    pub(super) fn persisted_record(
        &self,
        summary: &RunSummary,
        result: &Value,
    ) -> Result<PersistedVerification> {
        let cost = tool_run_output_cost_report(result)?;
        Ok(PersistedVerification {
            proof_level: self.proof_level,
            proof_verdict: PersistedProofVerdict::NotAttempted,
            backend: PersistedSandboxBackend::Model,
            language: None,
            harness_path: None,
            crash_evidence: None,
            duration_ms: run_duration_ms(summary),
            cost_usd: persisted_cost_usd(cost),
            notes: verification_notes(self.exploitable, self.confidence, cost),
            verification_run_id: Some(summary.run_id.clone()),
            verified_scan_id: Some(self.verified_scan_id.clone()),
            provenance: Some(VerificationProvenance {
                source_identity: self.source_identity.clone(),
                reproducer: None,
            }),
            created_at: String::new(),
        })
    }
}

fn parse_candidate(value: Option<&Value>, label: &str) -> Result<ModelProofCandidate> {
    serde_json::from_value(
        value
            .cloned()
            .with_context(|| format!("{label} is missing"))?,
    )
    .with_context(|| format!("{label} is invalid"))
}

fn run_duration_ms(summary: &RunSummary) -> u64 {
    summary
        .completed_at_unix
        .unwrap_or(summary.started_at_unix)
        .saturating_sub(summary.started_at_unix)
        .saturating_mul(1_000)
}

fn persisted_cost_usd(cost: RuntimeCostReport) -> f64 {
    cost.observed_usd_if_available().unwrap_or_default()
}

fn verification_notes(exploitable: bool, confidence: f64, cost: RuntimeCostReport) -> Vec<String> {
    let assessment = if exploitable {
        "likely_exploitable"
    } else {
        "likely_not_exploitable"
    };
    let mut notes = vec![format!(
        "static model exploitability review assessment={assessment} confidence={confidence:.3}; runtime verification was not attempted"
    )];
    let unresolved = match (cost.is_complete(), cost.is_unavailable()) {
        (true, _) => None,
        (false, true) => Some("provider cost unavailable"),
        (false, false) => Some("provider spend unresolved"),
    };
    if let Some(note) = unresolved {
        notes.push(note.to_string());
    }
    notes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_assessment_notes_preserve_both_conclusions() {
        let cost = RuntimeCostReport::known(crate::runtime::RuntimeCost::ZERO);

        assert!(verification_notes(true, 0.9, cost)[0].contains("likely_exploitable"));
        assert!(verification_notes(false, 0.8, cost)[0].contains("likely_not_exploitable"));
    }
}
