//! Persist a completed chain as a durable finding.
//!
//! This is what closes the loop: a chain that landed becomes a finding in the
//! shared store — visible in `findings:list`, reports, and the TUI like any
//! other — and a *completed* chain gets an empirical verification record at
//! proof level 4 (`Exploited`), because it was actually executed against the
//! live target, not merely reasoned about. A chain with no landed link writes
//! nothing.

use super::chain::ChainOutcome;
use super::play::PlayOutcome;
use crate::findings::{
    Finding, FindingEvidence, FindingStore, PersistedProofVerdict, PersistedSandboxBackend,
    PersistedVerification, Severity,
};
use anyhow::Result;
use std::path::Path;
use uuid::Uuid;

/// Write `outcome` to the findings store anchored at `workspace_root`.
/// Returns the finding id when a finding was written.
pub fn persist_chain_finding(
    store: &FindingStore,
    workspace_root: &Path,
    target_host: &str,
    backend: PersistedSandboxBackend,
    outcome: &ChainOutcome,
) -> Result<Option<i64>> {
    let landed: Vec<&PlayOutcome> = outcome.steps.iter().filter(|s| s.exploited).collect();
    if landed.is_empty() {
        return Ok(None);
    }
    let run_id = Uuid::new_v4().to_string();
    store.insert_scan_run(&run_id, workspace_root, "running")?;
    let finding = build_chain_finding(target_host, outcome, &landed);
    let finding_id = store.insert_finding(&run_id, &finding)?;
    if outcome.completed {
        store.save_verification(finding_id, &exploited_verification(backend, outcome))?;
    }
    store.complete_scan_run(&run_id, "completed", 1)?;
    Ok(Some(finding_id))
}

/// Map the transport's sandbox backend onto the persisted verification backend.
pub fn persisted_backend(backend: kuzushi_sandbox::SandboxBackend) -> PersistedSandboxBackend {
    match backend {
        kuzushi_sandbox::SandboxBackend::Bwrap => PersistedSandboxBackend::Bwrap,
        kuzushi_sandbox::SandboxBackend::Podman => PersistedSandboxBackend::Podman,
        kuzushi_sandbox::SandboxBackend::Plain => PersistedSandboxBackend::Plain,
    }
}

fn build_chain_finding(target_host: &str, outcome: &ChainOutcome, landed: &[&PlayOutcome]) -> Finding {
    let severity = if outcome.completed {
        Severity::Critical
    } else {
        Severity::High
    };
    let message = format!(
        "Live attack chain {:?} against {target_host}: {}",
        outcome.chain, outcome.summary
    );
    let mut finding = Finding::new_tool(
        "offense",
        format!("offense-chain/{}", outcome.chain),
        target_host,
        0,
        None,
        severity,
        message,
    );
    finding.evidence = landed.iter().map(|step| step_evidence(step, target_host)).collect();
    finding
}

fn step_evidence(step: &PlayOutcome, target_host: &str) -> FindingEvidence {
    FindingEvidence {
        kind: "live-chain-step".to_string(),
        file_path: target_host.to_string(),
        line: 0,
        snippet: step.summary.clone(),
        rationale: step.evidence.join(", "),
        confidence: 100,
    }
}

fn exploited_verification(
    backend: PersistedSandboxBackend,
    outcome: &ChainOutcome,
) -> PersistedVerification {
    PersistedVerification {
        proof_level: 4,
        proof_verdict: PersistedProofVerdict::Exploited,
        backend,
        language: None,
        harness_path: None,
        crash_evidence: Some(chain_evidence_blob(outcome)),
        duration_ms: 0,
        cost_usd: 0.0,
        notes: vec![format!("live attack chain {:?} completed", outcome.chain)],
        created_at: String::new(),
    }
}

fn chain_evidence_blob(outcome: &ChainOutcome) -> String {
    outcome
        .steps
        .iter()
        .map(|step| format!("{}: {} [{}]", step.play, step.summary, step.evidence.join(", ")))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(completed: bool, landed_steps: usize) -> ChainOutcome {
        let steps = (0..landed_steps)
            .map(|i| {
                PlayOutcome::new(format!("step-{i}"), "box.htb")
                    .exploited(format!("step {i} landed"), vec![format!("sig-{i}")])
            })
            .collect();
        ChainOutcome {
            chain: "bypass-idor-rce".to_string(),
            target: "box.htb".to_string(),
            steps,
            completed,
            summary: "chain summary".to_string(),
        }
    }

    #[test]
    fn completed_chain_persists_an_exploited_critical_finding() {
        let store = FindingStore::open_in_memory().unwrap();
        let id = persist_chain_finding(
            &store,
            Path::new("/tmp/ws"),
            "box.htb",
            PersistedSandboxBackend::Bwrap,
            &outcome(true, 3),
        )
        .unwrap();
        assert!(id.is_some());

        let findings = store.list_findings(10).unwrap();
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.severity, Severity::Critical);
        assert_eq!(finding.tool, "offense");
        assert_eq!(finding.evidence.len(), 3);
        let verification = store
            .get_latest_verification(id.unwrap())
            .unwrap()
            .expect("exploited verification");
        assert_eq!(verification.proof_level, 4);
        assert_eq!(verification.proof_verdict, PersistedProofVerdict::Exploited);
    }

    #[test]
    fn partial_chain_persists_high_finding_without_exploited_proof() {
        let store = FindingStore::open_in_memory().unwrap();
        let id = persist_chain_finding(
            &store,
            Path::new("/tmp/ws"),
            "box.htb",
            PersistedSandboxBackend::Plain,
            &outcome(false, 1),
        )
        .unwrap()
        .unwrap();
        let findings = store.list_findings(10).unwrap();
        assert_eq!(findings[0].severity, Severity::High);
        // No exploited verification for an incomplete chain.
        assert!(store.get_latest_verification(id).unwrap().is_none());
    }

    #[test]
    fn chain_with_no_landed_link_persists_nothing() {
        let store = FindingStore::open_in_memory().unwrap();
        let id = persist_chain_finding(
            &store,
            Path::new("/tmp/ws"),
            "box.htb",
            PersistedSandboxBackend::Plain,
            &outcome(false, 0),
        )
        .unwrap();
        assert!(id.is_none());
        assert!(store.list_findings(10).unwrap().is_empty());
    }
}
