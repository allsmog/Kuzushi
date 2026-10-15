//! Scan-to-scan comparison over the durable observation history.
//!
//! Legacy classes remain available for compatibility. Recorded observation
//! presence uses explicit coverage receipts and never establishes a fix.
//! A narrowed, partial or unrecorded scan cannot prove that an absent finding
//! was reassessed. Comparisons do not change finding decisions.

use super::super::persistence::{finding_stable_fp, FindingStore};
use crate::findings::Finding;
use anyhow::Result;
use std::collections::BTreeMap;
mod observation_presence;
pub use observation_presence::ScanObservationPresence;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanComparisonClass {
    /// Observed by the compare run only.
    New,
    /// Observed by both runs after the reconciler had marked it stale.
    Reopened,
    /// Observed by both runs.
    Persisting,
    /// Legacy deterministic-absence class, retained for compatibility.
    /// Use `observation_presence` for receipt-backed coverage; this is no fix verdict.
    Resolved,
    /// Legacy absence class whose deterministic coverage proof is missing.
    NotRescanned,
}

impl ScanComparisonClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Reopened => "reopened",
            Self::Persisting => "persisting",
            Self::Resolved => "resolved",
            Self::NotRescanned => "not_rescanned",
        }
    }
}

/// The mutable review-relevant surface of one finding in one run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanFindingSignature {
    pub severity: Option<String>,
    pub confidence: Option<String>,
    pub verdict: Option<String>,
}

impl ScanFindingSignature {
    fn of(finding: &Finding) -> Self {
        Self {
            severity: Some(finding.severity.as_str().to_string()),
            confidence: finding
                .triage
                .as_ref()
                .map(|triage| format!("{:.2}", triage.confidence)),
            verdict: finding
                .triage
                .as_ref()
                .map(|triage| triage.verdict.as_str().to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComparedFinding {
    pub stable_key: String,
    pub title: String,
    pub tool: String,
    pub file_path: String,
    pub class: ScanComparisonClass,
    /// For `NotRescanned`: the specific proof the compare run is missing.
    pub reason: Option<String>,
    /// For an absent finding, why the later run cannot establish reassessment.
    /// Independent of the legacy resolution classification and never proof of a fix.
    pub reassessment_block: Option<String>,
    pub before: Option<ScanFindingSignature>,
    pub after: Option<ScanFindingSignature>,
}

impl ComparedFinding {
    pub fn signature_changed(&self) -> bool {
        matches!((&self.before, &self.after), (Some(before), Some(after)) if before != after)
    }
}

/// A base/compare pair that looks like the same issue (same tool, rule, file,
/// and title) but carries a different identity. Kept out of every other
/// bucket: a re-keyed finding must not read as one resolve plus one new.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanUncertainMatch {
    pub base_key: String,
    pub compare_key: String,
    pub title: String,
    pub before: ScanFindingSignature,
    pub after: ScanFindingSignature,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanRunComparison {
    pub base_run_id: String,
    pub compare_run_id: String,
    pub base_status: String,
    pub compare_status: String,
    pub findings: Vec<ComparedFinding>,
    pub uncertain: Vec<ScanUncertainMatch>,
}

impl ScanRunComparison {
    pub fn count_of(&self, class: ScanComparisonClass) -> usize {
        self.findings
            .iter()
            .filter(|finding| finding.class == class)
            .count()
    }
}

/// Compares two recorded runs by durable finding identity.
pub fn compare_scan_runs(
    store: &FindingStore,
    base_run_id: &str,
    compare_run_id: &str,
) -> Result<ScanRunComparison> {
    let base = findings_by_stable_key(store, base_run_id)?;
    let compare = findings_by_stable_key(store, compare_run_id)?;
    let coverage = RetirementCoverage::load(store, base_run_id, compare_run_id)?;
    let reopened = store.reopened_stable_fps_for_run(compare_run_id)?;
    let uncertain = uncertain_matches(&base, &compare);
    let findings = classify_findings(&base, &compare, &coverage, &reopened, &uncertain);
    Ok(ScanRunComparison {
        base_run_id: base_run_id.to_string(),
        compare_run_id: compare_run_id.to_string(),
        base_status: coverage.base_status.clone(),
        compare_status: coverage.compare_status.clone(),
        findings,
        uncertain,
    })
}

fn findings_by_stable_key(store: &FindingStore, run_id: &str) -> Result<BTreeMap<String, Finding>> {
    let findings = store.v3_findings_for_scan_id(run_id)?;
    Ok(findings
        .into_iter()
        .map(|finding| (finding_stable_fp(&finding), finding))
        .collect())
}

mod classify;
mod uncertain;

use classify::{classify_findings, RetirementCoverage};
use uncertain::uncertain_matches;
