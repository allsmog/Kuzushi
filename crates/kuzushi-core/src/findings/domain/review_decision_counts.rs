use super::ReviewDecisionVerdict;
use serde::Serialize;

/// Effective terminal decisions. Source applicability is checked by the caller;
/// retained decisions needing reassessment must not enter these totals.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReviewDecisionCounts {
    pub confirmed: usize,
    pub to_fix: usize,
    pub rejected_false_positive: usize,
    pub suppressed: usize,
    pub deferred: usize,
    pub accepted_risk: usize,
}

impl ReviewDecisionCounts {
    pub fn total(self) -> usize {
        [
            self.confirmed,
            self.to_fix,
            self.rejected_false_positive,
            self.suppressed,
            self.deferred,
            self.accepted_risk,
        ]
        .into_iter()
        .sum()
    }

    pub fn confirmed_total(self) -> usize {
        self.confirmed + self.to_fix
    }

    pub(crate) fn record(&mut self, verdict: ReviewDecisionVerdict) {
        let count = match verdict {
            ReviewDecisionVerdict::Confirmed => &mut self.confirmed,
            ReviewDecisionVerdict::ToFix => &mut self.to_fix,
            ReviewDecisionVerdict::RejectedFalsePositive => &mut self.rejected_false_positive,
            ReviewDecisionVerdict::Suppressed => &mut self.suppressed,
            ReviewDecisionVerdict::Deferred => &mut self.deferred,
            ReviewDecisionVerdict::AcceptedRisk => &mut self.accepted_risk,
            ReviewDecisionVerdict::NeedsReview => return,
        };
        *count += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_terminal_verdict_keeps_its_category_and_unreviewed_stays_out() {
        let mut counts = ReviewDecisionCounts::default();
        for verdict in [
            ReviewDecisionVerdict::Confirmed,
            ReviewDecisionVerdict::ToFix,
            ReviewDecisionVerdict::RejectedFalsePositive,
            ReviewDecisionVerdict::Suppressed,
            ReviewDecisionVerdict::Deferred,
            ReviewDecisionVerdict::AcceptedRisk,
            ReviewDecisionVerdict::NeedsReview,
        ] {
            counts.record(verdict);
        }
        assert_eq!(counts.total(), 6);
        assert_eq!(counts.confirmed_total(), 2);
        assert_eq!(
            serde_json::to_value(counts).unwrap(),
            serde_json::json!({
                "confirmed": 1, "toFix": 1, "rejectedFalsePositive": 1,
                "suppressed": 1, "deferred": 1, "acceptedRisk": 1,
            })
        );
    }
}
