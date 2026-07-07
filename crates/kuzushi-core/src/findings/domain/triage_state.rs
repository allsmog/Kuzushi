//! The triage state machine: a pure, IO-free fold from the projected machine
//! lifecycle (`stable_findings.current_status`) plus the latest human review
//! decision into a single operator-facing `FindingTriageState`.
//!
//! Design invariant: `Fixed` and `Removed` are **machine-derived only**. They
//! are reachable exclusively through `StableLifecycleStatus::Stale`, which is
//! projected from a `FindingDisappeared` event that only the re-scan
//! reconciler emits. No human write API can assert `Fixed`/`Removed` — a
//! finding is "fixed" only because a re-scan that ran the same tool no longer
//! produces it.

use super::review_decision::{DismissReason, ReviewDecision, ReviewDecisionVerdict};
use super::TriageAuthor;
use serde::{Deserialize, Serialize};

/// Operator-facing triage lifecycle for a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum FindingTriageState {
    Open,
    Reviewing,
    Confirmed,
    ToFix,
    Dismissed { reason: DismissReason },
    /// Was confirmed/to-fix, and a re-scan no longer produces it. Machine-only.
    Fixed,
    /// Never confirmed, and a re-scan no longer produces it (rule/code drift).
    /// Machine-only.
    Removed,
}

impl FindingTriageState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Reviewing => "reviewing",
            Self::Confirmed => "confirmed",
            Self::ToFix => "to_fix",
            Self::Dismissed { .. } => "dismissed",
            Self::Fixed => "fixed",
            Self::Removed => "removed",
        }
    }

    pub fn is_dismissed(&self) -> bool {
        matches!(self, Self::Dismissed { .. })
    }

    /// Terminal states no longer need operator attention in the open queue.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Dismissed { .. } | Self::Fixed | Self::Removed | Self::Confirmed | Self::ToFix
        )
    }
}

/// The machine lifecycle projected into `stable_findings.current_status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StableLifecycleStatus {
    Open,
    Stale,
    Suppressed,
    Rekeyed,
}

impl StableLifecycleStatus {
    /// Parses the `stable_findings.current_status` projection value. Unknown
    /// values map to `Open` (the safe, attention-preserving default).
    pub fn from_current_status(value: &str) -> Self {
        match value.trim() {
            "stale" => Self::Stale,
            "suppressed" => Self::Suppressed,
            "rekeyed" => Self::Rekeyed,
            _ => Self::Open,
        }
    }
}

/// THE state machine fold. Pure and total.
pub fn derive_triage_state(
    lifecycle: StableLifecycleStatus,
    latest_human_decision: Option<&ReviewDecision>,
) -> FindingTriageState {
    let human = human_decision_state(latest_human_decision);
    match lifecycle {
        StableLifecycleStatus::Stale => resolve_stale_state(human),
        _ => human,
    }
}

/// Projects the latest human decision (ignoring automated triage) into the
/// non-stale portion of the state space.
fn human_decision_state(decision: Option<&ReviewDecision>) -> FindingTriageState {
    let Some(decision) = decision.filter(|d| d.author != TriageAuthor::Auto) else {
        return FindingTriageState::Open;
    };
    if let Some(reason) = decision.effective_dismiss_reason() {
        return FindingTriageState::Dismissed { reason };
    }
    match decision.verdict {
        ReviewDecisionVerdict::Confirmed => FindingTriageState::Confirmed,
        ReviewDecisionVerdict::ToFix => FindingTriageState::ToFix,
        ReviewDecisionVerdict::Deferred => FindingTriageState::Reviewing,
        ReviewDecisionVerdict::NeedsReview => FindingTriageState::Reviewing,
        // Dismissal-style verdicts are covered by effective_dismiss_reason above.
        ReviewDecisionVerdict::RejectedFalsePositive
        | ReviewDecisionVerdict::Suppressed
        | ReviewDecisionVerdict::AcceptedRisk => FindingTriageState::Open,
    }
}

/// Overlays the stale (re-scan-disappeared) machine fact onto the human state.
/// A dismissal survives disappearance (the human verdict is not erased); an
/// affirmed finding becomes `Fixed`; anything else becomes `Removed`.
fn resolve_stale_state(human: FindingTriageState) -> FindingTriageState {
    match human {
        FindingTriageState::Dismissed { reason } => FindingTriageState::Dismissed { reason },
        FindingTriageState::Confirmed | FindingTriageState::ToFix => FindingTriageState::Fixed,
        _ => FindingTriageState::Removed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decision(verdict: ReviewDecisionVerdict, author: TriageAuthor) -> ReviewDecision {
        ReviewDecision {
            verdict,
            author,
            confidence: 1.0,
            rationale: "r".to_string(),
            dismiss_reason: None,
            actor: None,
        }
    }

    fn dismissal(reason: DismissReason) -> ReviewDecision {
        ReviewDecision::dismissal(reason, "note", "operator")
    }

    #[test]
    fn open_with_no_decision_is_open() {
        assert_eq!(
            derive_triage_state(StableLifecycleStatus::Open, None),
            FindingTriageState::Open
        );
    }

    #[test]
    fn auto_only_decision_stays_open() {
        let d = decision(ReviewDecisionVerdict::Confirmed, TriageAuthor::Auto);
        assert_eq!(
            derive_triage_state(StableLifecycleStatus::Open, Some(&d)),
            FindingTriageState::Open
        );
    }

    #[test]
    fn human_needs_review_is_reviewing() {
        let d = decision(ReviewDecisionVerdict::NeedsReview, TriageAuthor::Human);
        assert_eq!(
            derive_triage_state(StableLifecycleStatus::Open, Some(&d)),
            FindingTriageState::Reviewing
        );
    }

    #[test]
    fn confirmed_and_to_fix() {
        let c = decision(ReviewDecisionVerdict::Confirmed, TriageAuthor::Human);
        let f = decision(ReviewDecisionVerdict::ToFix, TriageAuthor::Human);
        assert_eq!(
            derive_triage_state(StableLifecycleStatus::Open, Some(&c)),
            FindingTriageState::Confirmed
        );
        assert_eq!(
            derive_triage_state(StableLifecycleStatus::Open, Some(&f)),
            FindingTriageState::ToFix
        );
    }

    #[test]
    fn explicit_dismissal_carries_reason() {
        let d = dismissal(DismissReason::UsedInTests);
        assert_eq!(
            derive_triage_state(StableLifecycleStatus::Open, Some(&d)),
            FindingTriageState::Dismissed {
                reason: DismissReason::UsedInTests
            }
        );
    }

    #[test]
    fn legacy_verdicts_without_reason_map_to_dismissed() {
        for (verdict, reason) in [
            (
                ReviewDecisionVerdict::RejectedFalsePositive,
                DismissReason::FalsePositive,
            ),
            (
                ReviewDecisionVerdict::AcceptedRisk,
                DismissReason::AcceptableRisk,
            ),
            (ReviewDecisionVerdict::Suppressed, DismissReason::WontFix),
        ] {
            let d = decision(verdict, TriageAuthor::Human);
            assert_eq!(
                derive_triage_state(StableLifecycleStatus::Open, Some(&d)),
                FindingTriageState::Dismissed { reason }
            );
        }
    }

    #[test]
    fn stale_confirmed_is_fixed() {
        let c = decision(ReviewDecisionVerdict::Confirmed, TriageAuthor::Human);
        assert_eq!(
            derive_triage_state(StableLifecycleStatus::Stale, Some(&c)),
            FindingTriageState::Fixed
        );
        let f = decision(ReviewDecisionVerdict::ToFix, TriageAuthor::Human);
        assert_eq!(
            derive_triage_state(StableLifecycleStatus::Stale, Some(&f)),
            FindingTriageState::Fixed
        );
    }

    #[test]
    fn stale_without_confirmation_is_removed() {
        assert_eq!(
            derive_triage_state(StableLifecycleStatus::Stale, None),
            FindingTriageState::Removed
        );
        let reviewing = decision(ReviewDecisionVerdict::NeedsReview, TriageAuthor::Human);
        assert_eq!(
            derive_triage_state(StableLifecycleStatus::Stale, Some(&reviewing)),
            FindingTriageState::Removed
        );
        let auto = decision(ReviewDecisionVerdict::Confirmed, TriageAuthor::Auto);
        assert_eq!(
            derive_triage_state(StableLifecycleStatus::Stale, Some(&auto)),
            FindingTriageState::Removed,
            "auto-only confirmation never earns Fixed"
        );
    }

    #[test]
    fn stale_dismissed_stays_dismissed() {
        let d = dismissal(DismissReason::FalsePositive);
        assert_eq!(
            derive_triage_state(StableLifecycleStatus::Stale, Some(&d)),
            FindingTriageState::Dismissed {
                reason: DismissReason::FalsePositive
            }
        );
    }

    #[test]
    fn reopened_finding_returns_to_human_state() {
        // Re-observation flips current_status stale -> open; the state then
        // falls back to the human decision, automatically leaving Fixed/Removed.
        let c = decision(ReviewDecisionVerdict::Confirmed, TriageAuthor::Human);
        assert_eq!(
            derive_triage_state(StableLifecycleStatus::Open, Some(&c)),
            FindingTriageState::Confirmed
        );
    }

    #[test]
    fn dismiss_reason_round_trip() {
        for reason in [
            DismissReason::FalsePositive,
            DismissReason::AcceptableRisk,
            DismissReason::WontFix,
            DismissReason::UsedInTests,
            DismissReason::NoTimeToFix,
        ] {
            assert_eq!(DismissReason::from_str(reason.as_str()), Some(reason));
        }
        assert_eq!(DismissReason::from_str("nonsense"), None);
    }
}
