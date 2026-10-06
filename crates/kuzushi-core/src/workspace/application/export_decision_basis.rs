//! Which observed run and source snapshot each review decision was made
//! against. Derived from the decision's recorded event watermark, so it needs
//! no new event fields and never rewrites a decision.
use super::*;
use crate::findings::{ObservedSnapshot, ReviewDecisionRecord};
use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceReviewDecisionBasis {
    pub run_id: String,
    pub snapshot_hash: String,
    /// A newer observation of the same finding, recorded after the decision.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub later_observation: Option<WorkspaceObservedSource>,
    /// The finding was observed again on different source after the decision,
    /// so the decision may not describe the current code.
    pub source_changed_since_decision: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceObservedSource {
    pub run_id: String,
    pub snapshot_hash: String,
}

pub(super) fn attach_review_decision_basis(
    store: &FindingStore,
    findings: &[Finding],
    records: &mut [WorkspaceFindingExportRecord],
) -> Result<()> {
    let decisions = store.list_review_decisions_for_findings(findings)?;
    // Records are in review-priority order while findings keep store order,
    // so each record is matched to its own finding by fingerprint.
    let by_fingerprint = findings
        .iter()
        .map(|finding| (finding.fingerprint.as_str(), finding))
        .collect::<HashMap<_, _>>();
    for record in records {
        let Some(finding) = by_fingerprint.get(record.fingerprint.as_str()) else {
            continue;
        };
        record.review_decision_basis = decision_basis(store, finding, &decisions)?;
    }
    Ok(())
}

fn decision_basis(
    store: &FindingStore,
    finding: &Finding,
    decisions: &[ReviewDecisionRecord],
) -> Result<Option<WorkspaceReviewDecisionBasis>> {
    let Some(watermark) = latest_decision_watermark(finding, decisions) else {
        return Ok(None);
    };
    let stable_fp = crate::findings::finding_stable_fp(finding);
    let Some(decided) = store.observed_snapshot_at(&stable_fp, watermark)? else {
        return Ok(None);
    };
    let latest = store.observed_snapshot_at(&stable_fp, u64::MAX)?;
    Ok(Some(basis(decided, latest)))
}

fn basis(
    decided: ObservedSnapshot,
    latest: Option<ObservedSnapshot>,
) -> WorkspaceReviewDecisionBasis {
    let later = latest.filter(|latest| latest.created_seq > decided.created_seq);
    WorkspaceReviewDecisionBasis {
        source_changed_since_decision: later
            .as_ref()
            .is_some_and(|later| later.snapshot_hash != decided.snapshot_hash),
        later_observation: later.map(|later| WorkspaceObservedSource {
            run_id: later.run_id,
            snapshot_hash: later.snapshot_hash,
        }),
        run_id: decided.run_id,
        snapshot_hash: decided.snapshot_hash,
    }
}

/// The most recent decision that records the event it was made at.
fn latest_decision_watermark(finding: &Finding, decisions: &[ReviewDecisionRecord]) -> Option<u64> {
    decisions
        .iter()
        .filter(|record| decides(record, finding))
        .max_by_key(|record| record.id)
        .and_then(|record| record.provenance.as_ref())
        .and_then(|provenance| provenance.read_watermark)
}

fn decides(record: &ReviewDecisionRecord, finding: &Finding) -> bool {
    finding.id == Some(record.finding_id)
        || (record.identity_id.is_some() && record.identity_id == finding.identity_id)
}

#[cfg(test)]
#[path = "tests/export_decision_basis.rs"]
mod tests;
