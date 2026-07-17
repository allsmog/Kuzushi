use crate::findings::{PersistedProofVerdict, PersistedSandboxBackend, PersistedVerification};
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
        let proof = parse_candidate(result.get("proof"), "proof snapshot")?;
        anyhow::ensure!(
            data == nested && nested == proof,
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
            (1..=4).contains(&self.proof_level),
            "proof level is outside 1..=4"
        );
        anyhow::ensure!(
            self.confidence.is_finite() && (0.0..=1.0).contains(&self.confidence),
            "proof confidence is outside 0..=1"
        );
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

    pub(super) fn persisted_record(
        &self,
        summary: &RunSummary,
        result: &Value,
    ) -> Result<PersistedVerification> {
        let cost = tool_run_output_cost_report(result)?;
        Ok(PersistedVerification {
            proof_level: self.proof_level,
            proof_verdict: self.proof_verdict,
            backend: PersistedSandboxBackend::Model,
            language: None,
            harness_path: None,
            crash_evidence: None,
            duration_ms: run_duration_ms(summary),
            cost_usd: persisted_cost_usd(cost),
            notes: verification_notes(self.confidence, cost),
            verification_run_id: Some(summary.run_id.clone()),
            verified_scan_id: Some(self.verified_scan_id.clone()),
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

fn verification_notes(confidence: f64, cost: RuntimeCostReport) -> Vec<String> {
    let mut notes = vec![format!(
        "model exploitability review confidence={confidence:.3}"
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
