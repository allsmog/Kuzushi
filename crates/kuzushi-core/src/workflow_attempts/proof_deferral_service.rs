//! Recording an operator's decision to defer empirical proof.
//!
//! A deferral is an operator decision, never evidence: it changes what the
//! journey still owes the operator, and it never promotes proof confidence,
//! the proof ladder, or a verification verdict. The shell and the headless
//! CLI both enter here so the gate (review must be complete, the finding must
//! carry a durable discovery generation) and the ledger write stay identical.

use super::{
    append_proof_deferral, load_phase_attempt_ledger, PhaseTargetSnapshot, ProofDeferralRecorded,
    ProofDeferralView,
};
use crate::findings::{finding_is_review_actionable, resolve_finding_alias, Finding, FindingStore};
use crate::workspace::WorkspaceTarget;
use anyhow::{Context, Result};

/// What the operator asked to defer, in their own words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofDeferralRequest {
    /// Finding alias (`F-0001`), full fingerprint, or fingerprint prefix.
    pub reference: String,
    pub reason: String,
}

/// The durable receipt for one recorded deferral.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedProofDeferral {
    /// The exact discovery generation the deferral is bound to.
    pub scan_id: String,
    /// Durable identity when the finding has one, else its fingerprint.
    pub subject: String,
    pub deferral: ProofDeferralRecorded,
}

/// Resolve, gate, and append one human proof deferral for `workspace`.
pub fn record_proof_deferral(
    workspace: &WorkspaceTarget,
    request: &ProofDeferralRequest,
) -> Result<RecordedProofDeferral> {
    let store = FindingStore::open(workspace.findings_db_path())?;
    let finding = resolve_deferral_subject(&store, &request.reference)?;
    ensure_review_complete(&store, &finding)?;
    let scan_id = discovery_generation(&finding)?;
    let subject = finding
        .identity_id
        .clone()
        .unwrap_or_else(|| finding.fingerprint.clone());
    let deferral = ProofDeferralRecorded::human(
        finding.fingerprint,
        finding.identity_id,
        scan_id.clone(),
        PhaseTargetSnapshot::capture(workspace.root()),
        request.reason.trim(),
    );
    append_proof_deferral(workspace.root(), deferral.clone())?;
    Ok(RecordedProofDeferral {
        scan_id,
        subject,
        deferral,
    })
}

/// Aliases are positional over the sorted whole ledger, so they resolve there
/// before any fingerprint round-trip: colliding fingerprints would otherwise
/// swap in a sibling finding at a different line than the alias names.
fn resolve_deferral_subject(store: &FindingStore, reference: &str) -> Result<Finding> {
    let all_findings = store.list_all_findings()?;
    if let Some(finding) = resolve_finding_alias(&all_findings, reference) {
        return Ok(finding);
    }
    store
        .get_finding_by_reference(reference)?
        .with_context(|| format!("no finding matches {reference:?}"))
}

fn ensure_review_complete(store: &FindingStore, finding: &Finding) -> Result<()> {
    let decisions = store.list_review_decisions_for_findings(std::slice::from_ref(finding))?;
    anyhow::ensure!(
        finding_is_review_actionable(finding, &decisions),
        "finding is not review-actionable; complete Review before deferring proof"
    );
    Ok(())
}

fn discovery_generation(finding: &Finding) -> Result<String> {
    finding
        .scan_id
        .as_deref()
        .map(str::trim)
        .filter(|scan_id| !scan_id.is_empty())
        .map(str::to_string)
        .context("finding has no durable discovery generation; scan it before deferring proof")
}

/// The deferral recorded for one finding at the target's current revision, if
/// any. Headless callers read the ledger here; the shell already holds a
/// hydrated ledger and projects the same view from it.
pub fn proof_deferral_view_for_finding(
    workspace: &WorkspaceTarget,
    finding: &Finding,
) -> Result<Option<ProofDeferralView>> {
    let Ok(scan_id) = discovery_generation(finding) else {
        return Ok(None);
    };
    let ledger = load_phase_attempt_ledger(workspace.root())?;
    Ok(ledger.proof_deferral_view_for(
        &PhaseTargetSnapshot::capture(workspace.root()),
        &finding.fingerprint,
        finding.identity_id.as_deref(),
        &scan_id,
    ))
}
