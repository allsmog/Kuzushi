use std::collections::BTreeSet;

use crate::review_yield::domain::{classify_cutoff, label_class, CutoffQuality, LabelClass};
use crate::review_yield::persistence::DecisionRow;

/// The label chosen for one durable identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelSelection {
    pub event_seq: u64,
    pub event_hash: String,
    pub verdict: String,
    pub class: u8,
    pub cutoff: u64,
    pub cutoff_quality: CutoffQuality,
}

/// What the census records for one identity's human decisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityOutcome {
    Labeled(Box<LabelSelection>),
    /// Human reviewers disagreed on whether the finding is real. Fail closed:
    /// counted and excluded, never resolved by recency.
    Conflicted,
    /// Binary human decisions exist, but none carries a usable read cutoff.
    MissingExactCutoff,
    /// Only policy outcomes (accepted risk, suppressed, deferred, open).
    NoEligibleLabel,
}

/// Picks the label for one identity from its human decisions, which must
/// already be ordered by decision event sequence.
pub fn select_identity_label(decisions: &[&DecisionRow]) -> IdentityOutcome {
    let binary: Vec<&&DecisionRow> = decisions
        .iter()
        .filter(|decision| binary_code(decision).is_some())
        .collect();
    if binary.is_empty() {
        return IdentityOutcome::NoEligibleLabel;
    }
    if has_conflict(&binary) {
        return IdentityOutcome::Conflicted;
    }
    binary
        .iter()
        .find_map(|decision| eligible_selection(decision))
        .map_or(IdentityOutcome::MissingExactCutoff, |selection| {
            IdentityOutcome::Labeled(Box::new(selection))
        })
}

/// Human decisions that moved an identity into a policy outcome after a binary
/// verdict. Informational only — not a label conflict.
pub fn policy_transition_count(decisions: &[&DecisionRow]) -> u64 {
    decisions
        .iter()
        .filter(|decision| label_class(decision.verdict) == LabelClass::Excluded)
        .count() as u64
}

fn binary_code(decision: &DecisionRow) -> Option<u8> {
    label_class(decision.verdict).binary_code()
}

fn has_conflict(decisions: &[&&DecisionRow]) -> bool {
    decisions
        .iter()
        .filter_map(|decision| binary_code(decision))
        .collect::<BTreeSet<u8>>()
        .len()
        > 1
}

fn eligible_selection(decision: &DecisionRow) -> Option<LabelSelection> {
    let provenance = decision.provenance.as_ref()?;
    let quality = classify_cutoff(provenance.read_watermark, provenance.event_seq);
    let cutoff = provenance.read_watermark.filter(|_| quality.is_eligible())?;
    Some(LabelSelection {
        event_seq: provenance.event_seq,
        event_hash: provenance.event_hash.clone(),
        verdict: decision.verdict.as_str().to_string(),
        class: binary_code(decision)?,
        cutoff,
        cutoff_quality: quality,
    })
}
