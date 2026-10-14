//! Which observed run and source snapshot each review decision was made
//! against. Derived from the decision's recorded event watermark, so it needs
//! no new event fields and never rewrites a decision.
use super::*;
use crate::findings::ObservedSnapshot;
use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceReviewDecisionBasis {
    pub run_id: String,
    pub snapshot_hash: String,
    /// Recorded Git metadata, never inferred from the current checkout.
    pub source_git: Option<crate::RunTargetGitMetadata>,
    /// A newer observation of the same finding, recorded after the decision.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub later_observation: Option<WorkspaceObservedSource>,
    /// The finding was observed again on different source after the decision,
    /// so the decision may not describe the current code.
    pub source_changed_since_decision: bool,
    /// Compares captured cited files, not complete repository coverage. A
    /// missing capture remains unknown even when snapshot ids differ.
    pub source_comparison: WorkspaceReviewSourceComparison,
    pub source_applicability: super::WorkspaceReviewSourceApplicability,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceReviewSourceComparison {
    NotReobserved,
    SameCitedSource,
    DifferentCitedSource,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceObservedSource {
    pub run_id: String,
    pub snapshot_hash: String,
    pub source_git: Option<crate::RunTargetGitMetadata>,
}

pub(super) fn attach_review_decision_basis(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    findings: &[Finding],
    reviews: &[Option<WorkspaceFindingReviewContext>],
    records: &mut [WorkspaceFindingExportRecord],
) -> Result<()> {
    let mut reader = super::review_source_applicability::ReviewSourceReader::new(workspace);
    // Records are in review-priority order while findings keep store order,
    // so each record is matched to its own finding by fingerprint.
    let by_fingerprint = findings
        .iter()
        .zip(reviews)
        .map(|(finding, review)| (finding.fingerprint.as_str(), (finding, review.as_ref())))
        .collect::<HashMap<_, _>>();
    for record in records {
        let Some((finding, review)) = by_fingerprint.get(record.fingerprint.as_str()) else {
            continue;
        };
        record.review_decision_basis = decision_basis(store, finding, *review)?;
        if let Some(basis) = record.review_decision_basis.as_mut() {
            reader.attach_recorded_source(basis);
        }
    }
    Ok(())
}

pub(super) fn decision_basis(
    store: &FindingStore,
    finding: &Finding,
    review: Option<&WorkspaceFindingReviewContext>,
) -> Result<Option<WorkspaceReviewDecisionBasis>> {
    let Some(watermark) = review.and_then(|review| review.read_watermark) else {
        return Ok(None);
    };
    decision_basis_at(
        store,
        &crate::findings::finding_stable_fp(finding),
        watermark,
        u64::MAX,
    )
}

fn decision_basis_at(
    store: &FindingStore,
    stable_fp: &str,
    watermark: u64,
    observation_watermark: u64,
) -> Result<Option<WorkspaceReviewDecisionBasis>> {
    let Some(decided) = store.observed_snapshot_at(stable_fp, watermark)? else {
        return Ok(None);
    };
    let latest = store.observed_snapshot_at(stable_fp, observation_watermark)?;
    let comparison = compare_cited_sources(store, stable_fp, &decided, latest.as_ref())?;
    Ok(Some(basis(decided, latest, comparison)))
}

fn compare_cited_sources(
    store: &FindingStore,
    stable_fp: &str,
    decided: &ObservedSnapshot,
    latest: Option<&ObservedSnapshot>,
) -> Result<WorkspaceReviewSourceComparison> {
    let Some(later) = latest.filter(|latest| latest.created_seq > decided.created_seq) else {
        return Ok(WorkspaceReviewSourceComparison::NotReobserved);
    };
    let before = store.observed_file_identity_at(stable_fp, decided.created_seq)?;
    let after = store.observed_file_identity_at(stable_fp, later.created_seq)?;
    Ok(compare_file_identities(before, after))
}

fn compare_file_identities(
    before: Option<(String, String)>,
    after: Option<(String, String)>,
) -> WorkspaceReviewSourceComparison {
    match (before, after) {
        (Some(before), Some(after)) if before == after => {
            WorkspaceReviewSourceComparison::SameCitedSource
        }
        (Some(_), Some(_)) => WorkspaceReviewSourceComparison::DifferentCitedSource,
        _ => WorkspaceReviewSourceComparison::Unknown,
    }
}

/// Reads the source behind the exact decision displayed by a caller, with
/// observations bounded to its ledger view. It neither writes nor re-triages.
pub fn read_finding_review_source(
    workspace: &WorkspaceTarget,
    stable_fp: &str,
    decision_watermark: u64,
    observation_watermark: Option<u64>,
) -> Result<Option<WorkspaceReviewDecisionBasis>> {
    let path = workspace.findings_db_path();
    if !path.exists() {
        return Ok(None);
    }
    let store = FindingStore::open_read_only(path)?;
    let mut basis = decision_basis_at(
        &store,
        stable_fp,
        decision_watermark,
        observation_watermark.unwrap_or(u64::MAX),
    )?;
    if let Some(basis) = basis.as_mut() {
        super::review_source_applicability::ReviewSourceReader::new(workspace)
            .attach_recorded_source(basis);
    }
    Ok(basis)
}

fn basis(
    decided: ObservedSnapshot,
    latest: Option<ObservedSnapshot>,
    source_comparison: WorkspaceReviewSourceComparison,
) -> WorkspaceReviewDecisionBasis {
    let later = latest.filter(|latest| latest.created_seq > decided.created_seq);
    WorkspaceReviewDecisionBasis {
        source_changed_since_decision: source_comparison
            == WorkspaceReviewSourceComparison::DifferentCitedSource,
        source_comparison,
        source_applicability: match source_comparison {
            WorkspaceReviewSourceComparison::NotReobserved => {
                super::WorkspaceReviewSourceApplicability::LatestObservation
            }
            WorkspaceReviewSourceComparison::DifferentCitedSource => {
                super::WorkspaceReviewSourceApplicability::ReassessmentRequired
            }
            _ => super::WorkspaceReviewSourceApplicability::LaterSourceUnverified,
        },
        later_observation: later.map(|later| WorkspaceObservedSource {
            run_id: later.run_id,
            snapshot_hash: later.snapshot_hash,
            source_git: None,
        }),
        run_id: decided.run_id,
        snapshot_hash: decided.snapshot_hash,
        source_git: None,
    }
}

#[cfg(test)]
#[path = "tests/export_decision_basis.rs"]
mod tests;
