use crate::findings::{Finding, PersistedSandboxBackend, PersistedVerification};
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::path::Path;

pub(super) fn validate(
    target: &Path,
    finding: &Finding,
    run_id: &str,
    result: &Value,
) -> Result<()> {
    let proof = finding
        .verification
        .as_ref()
        .context("empirical proof was not persisted")?;
    anyhow::ensure!(
        proof.backend != PersistedSandboxBackend::Model,
        "model assessment is not empirical verification"
    );
    anyhow::ensure!(
        proof.verification_run_id.as_deref() == Some(run_id),
        "empirical proof does not belong to the selected run"
    );
    anyhow::ensure!(
        proof.is_current_for_scan(finding.scan_id.as_deref()),
        "empirical proof belongs to a stale finding generation"
    );
    validate_snapshot(finding, proof, result)?;
    validate_source(target, proof)
}

fn validate_snapshot(
    finding: &Finding,
    proof: &PersistedVerification,
    result: &Value,
) -> Result<()> {
    anyhow::ensure!(
        result.get("ok") == Some(&json!(true)),
        "empirical result is not successful"
    );
    anyhow::ensure!(
        result.get("status") == Some(&json!("completed")),
        "empirical result is not completed"
    );
    let expected = json!({
        "kind": "empirical-verification", "empirical": true,
        "fingerprint": finding.fingerprint, "proofLevel": proof.proof_level,
        "proofVerdict": proof.proof_verdict.as_str(), "backend": format!("{:?}", proof.backend),
        "durationMs": proof.duration_ms, "costUsd": proof.cost_usd, "provenance": proof.provenance,
    });
    anyhow::ensure!(
        result.get("proof") == Some(&expected),
        "empirical snapshot differs from the durable finding proof"
    );
    Ok(())
}

fn validate_source(target: &Path, proof: &PersistedVerification) -> Result<()> {
    if !proof.has_terminal_runtime_verification() {
        // An unavailable backend records NotAttempted, which is not a proof
        // claim and need not manufacture source/reproducer provenance.
        return Ok(());
    }
    let provenance = proof
        .provenance
        .as_ref()
        .context("empirical proof has no source provenance")?;
    provenance.validate()?;
    let current = crate::verification::capture_verification_source_identity(target)?;
    anyhow::ensure!(
        current == provenance.source_identity,
        "empirical proof source identity is stale for the current workspace"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn terminal_receipt_requires_the_same_current_source_tree() {
        let target = tempfile::tempdir().unwrap();
        std::fs::write(target.path().join("source.rs"), "fn original() {}\n").unwrap();
        let source_identity =
            crate::verification::capture_verification_source_identity(target.path()).unwrap();
        let mut proof = crate::verification::VerificationOutcome::not_attempted(
            kuzushi_sandbox::SandboxBackend::Bwrap,
            "test-only source check",
        )
        .to_persisted();
        proof.proof_verdict = crate::findings::PersistedProofVerdict::NotReproduced;
        proof.provenance = Some(crate::findings::VerificationProvenance {
            source_identity,
            reproducer: None,
        });
        validate_source(target.path(), &proof).unwrap();
        std::fs::write(target.path().join("source.rs"), "fn changed() {}\n").unwrap();
        assert!(validate_source(target.path(), &proof)
            .unwrap_err()
            .to_string()
            .contains("stale"));
    }
}
