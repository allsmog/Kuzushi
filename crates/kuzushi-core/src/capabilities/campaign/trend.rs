//! Workspace effectiveness trend fold: FP rate and cost per confirmed
//! finding, computed from artifacts that already exist — review-decision
//! records and campaign job spend. Pure, so the cockpit deck, the Report
//! route, and `campaign:status` render the exact same numbers.

use super::snapshot::{campaign_ids, load_campaign_snapshot};
use crate::findings::{ReviewDecisionRecord, ReviewDecisionVerdict};
use std::collections::BTreeMap;
use std::path::Path;

/// One workspace-level trend snapshot. Rates are derived on demand so a
/// zero denominator stays an honest `None` instead of a fake 0%.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct TrendMetrics {
    /// Findings whose LATEST review decision is anything but needs-review.
    pub decided_findings: usize,
    /// Findings whose latest decision is rejected-false-positive.
    pub rejected_false_positives: usize,
    /// Findings whose latest decision confirms them (Confirmed or ToFix).
    pub confirmed_findings: usize,
    /// Summed dispatcher job spend across every readable campaign.
    pub campaign_spend_usd: f64,
    /// True when the observed spend is only a lower bound.
    pub provider_spend_unresolved: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct WorkspaceCampaignSpend {
    pub observed_usd: f64,
    pub provider_spend_unresolved: bool,
}

impl TrendMetrics {
    pub fn fp_rate(&self) -> Option<f64> {
        (self.decided_findings > 0)
            .then(|| self.rejected_false_positives as f64 / self.decided_findings as f64)
    }

    pub fn cost_per_confirmed_usd(&self) -> Option<f64> {
        (self.confirmed_findings > 0)
            .then(|| self.campaign_spend_usd / self.confirmed_findings as f64)
    }

    /// Compact one-line strip shared verbatim by the campaign deck and the
    /// Report route, e.g.
    /// `TREND  FP rate 25% (1/4) · 2 confirmed · $32.26 spent · $16.13/confirmed`.
    pub fn strip_label(&self) -> String {
        format!(
            "TREND  FP rate {} · {} confirmed · {} · {}",
            self.fp_rate_label(),
            self.confirmed_findings,
            self.spend_label(),
            self.cost_per_confirmed_label(),
        )
    }

    fn spend_label(&self) -> String {
        if self.provider_spend_unresolved {
            return format!(">=${:.2} spent (incomplete)", self.campaign_spend_usd);
        }
        format!("${:.2} spent", self.campaign_spend_usd)
    }

    fn fp_rate_label(&self) -> String {
        match self.fp_rate() {
            Some(rate) => format!(
                "{:.0}% ({}/{})",
                rate * 100.0,
                self.rejected_false_positives,
                self.decided_findings
            ),
            None => "— (no decisions)".to_string(),
        }
    }

    fn cost_per_confirmed_label(&self) -> String {
        match self.cost_per_confirmed_usd() {
            Some(cost) if self.provider_spend_unresolved => format!(">=${cost:.2}/confirmed"),
            Some(cost) => format!("${cost:.2}/confirmed"),
            None => "—/confirmed".to_string(),
        }
    }
}

/// Fold decision records with campaign spend. A finding's latest record wins
/// (same reversal rule as the coverage matrix's confirmed fold), so a
/// confirm followed by a rejection counts as one rejected false positive.
pub fn trend_metrics(records: &[ReviewDecisionRecord], campaign_spend_usd: f64) -> TrendMetrics {
    trend_metrics_with_spend(
        records,
        WorkspaceCampaignSpend {
            observed_usd: campaign_spend_usd,
            provider_spend_unresolved: false,
        },
    )
}

pub fn trend_metrics_with_spend(
    records: &[ReviewDecisionRecord],
    spend: WorkspaceCampaignSpend,
) -> TrendMetrics {
    let mut metrics = TrendMetrics {
        campaign_spend_usd: spend.observed_usd,
        provider_spend_unresolved: spend.provider_spend_unresolved,
        ..TrendMetrics::default()
    };
    for verdict in latest_verdicts(records).values() {
        match verdict {
            ReviewDecisionVerdict::NeedsReview => continue,
            ReviewDecisionVerdict::Confirmed | ReviewDecisionVerdict::ToFix => {
                metrics.confirmed_findings += 1;
            }
            ReviewDecisionVerdict::RejectedFalsePositive => {
                metrics.rejected_false_positives += 1;
            }
            _ => {}
        }
        metrics.decided_findings += 1;
    }
    metrics
}

/// Latest decision per finding, by decision record id. This is THE reversal
/// rule: a confirm followed by a rejection is a rejection. Shared by the
/// trend fold and the confirmed-findings SARIF export so both report the
/// same set of decided findings.
pub fn latest_verdicts(records: &[ReviewDecisionRecord]) -> BTreeMap<i64, ReviewDecisionVerdict> {
    let mut latest: BTreeMap<i64, (i64, ReviewDecisionVerdict)> = BTreeMap::new();
    for record in records {
        let entry = latest
            .entry(record.finding_id)
            .or_insert((record.id, record.decision.verdict));
        if record.id >= entry.0 {
            *entry = (record.id, record.decision.verdict);
        }
    }
    latest
        .into_iter()
        .map(|(finding_id, (_, verdict))| (finding_id, verdict))
        .collect()
}

/// Finding ids whose LATEST review decision confirms them (`Confirmed` or
/// `ToFix`). One shared definition of "confirmed" for the SARIF export and
/// the CI gate, so they can never disagree with the trend fold.
pub fn latest_confirmed_finding_ids(
    records: &[ReviewDecisionRecord],
) -> std::collections::BTreeSet<i64> {
    latest_verdicts(records)
        .into_iter()
        .filter(|(_, verdict)| {
            matches!(
                verdict,
                ReviewDecisionVerdict::Confirmed | ReviewDecisionVerdict::ToFix
            )
        })
        .map(|(finding_id, _)| finding_id)
        .collect()
}

/// Summed job spend across every readable campaign. Unreadable campaign
/// directories are skipped — one corrupt plan must not blind the trend.
pub fn workspace_campaign_spend(root: &Path) -> f64 {
    workspace_campaign_spend_report(root).observed_usd
}

pub fn workspace_campaign_spend_report(root: &Path) -> WorkspaceCampaignSpend {
    let Ok(ids) = campaign_ids(root) else {
        return WorkspaceCampaignSpend {
            provider_spend_unresolved: true,
            ..WorkspaceCampaignSpend::default()
        };
    };
    let mut spend = WorkspaceCampaignSpend::default();
    for campaign_id in ids {
        match load_campaign_snapshot(root, &campaign_id) {
            Ok(snapshot) => {
                spend.observed_usd += snapshot.total_cost_usd;
                spend.provider_spend_unresolved |= snapshot.provider_spend_unresolved;
            }
            Err(_) => spend.provider_spend_unresolved = true,
        }
    }
    spend.observed_usd += 0.0;
    spend
}

pub fn trend_json(metrics: &TrendMetrics) -> serde_json::Value {
    serde_json::json!({
        "decidedFindings": metrics.decided_findings,
        "rejectedFalsePositives": metrics.rejected_false_positives,
        "confirmedFindings": metrics.confirmed_findings,
        "fpRate": metrics.fp_rate(),
        "campaignSpendUsd": metrics.campaign_spend_usd,
        "providerSpendUnresolved": metrics.provider_spend_unresolved,
        "costPerConfirmedUsd": metrics.cost_per_confirmed_usd(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{ReviewDecision, TriageAuthor};

    fn record(id: i64, finding_id: i64, verdict: ReviewDecisionVerdict) -> ReviewDecisionRecord {
        ReviewDecisionRecord {
            id,
            finding_id,
            identity_id: None,
            decision: ReviewDecision {
                verdict,
                author: TriageAuthor::Human,
                confidence: 1.0,
                rationale: String::new(),
                dismiss_reason: None,
                actor: None,
            },
            triage_verdict: None,
            created_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn latest_decision_per_finding_wins_and_needs_review_stays_undecided() {
        let records = vec![
            // finding 1: confirmed, then reversed to rejected — counts as FP.
            record(1, 1, ReviewDecisionVerdict::Confirmed),
            record(4, 1, ReviewDecisionVerdict::RejectedFalsePositive),
            record(2, 2, ReviewDecisionVerdict::ToFix),
            record(3, 3, ReviewDecisionVerdict::Deferred),
            record(5, 4, ReviewDecisionVerdict::NeedsReview),
        ];

        let metrics = trend_metrics(&records, 30.0);

        assert_eq!(metrics.decided_findings, 3);
        assert_eq!(metrics.rejected_false_positives, 1);
        assert_eq!(metrics.confirmed_findings, 1);
        assert!((metrics.fp_rate().unwrap() - 1.0 / 3.0).abs() < 1e-9);
        assert_eq!(metrics.cost_per_confirmed_usd(), Some(30.0));
    }

    #[test]
    fn zero_denominators_render_as_honest_dashes_not_fake_rates() {
        let metrics = trend_metrics(&[], 5.0);

        assert_eq!(metrics.fp_rate(), None);
        assert_eq!(metrics.cost_per_confirmed_usd(), None);
        assert_eq!(
            metrics.strip_label(),
            "TREND  FP rate — (no decisions) · 0 confirmed · $5.00 spent · —/confirmed"
        );
    }

    #[test]
    fn strip_label_folds_rate_spend_and_unit_cost_into_one_line() {
        let records = vec![
            record(1, 1, ReviewDecisionVerdict::Confirmed),
            record(2, 2, ReviewDecisionVerdict::Confirmed),
            record(3, 3, ReviewDecisionVerdict::RejectedFalsePositive),
            record(4, 4, ReviewDecisionVerdict::Deferred),
        ];

        let metrics = trend_metrics(&records, 32.26);

        assert_eq!(
            metrics.strip_label(),
            "TREND  FP rate 25% (1/4) · 2 confirmed · $32.26 spent · $16.13/confirmed"
        );
    }

    #[test]
    fn unresolved_spend_renders_as_an_incomplete_lower_bound() {
        let metrics = trend_metrics_with_spend(
            &[record(1, 1, ReviewDecisionVerdict::Confirmed)],
            WorkspaceCampaignSpend {
                observed_usd: 3.25,
                provider_spend_unresolved: true,
            },
        );

        assert_eq!(
            metrics.strip_label(),
            "TREND  FP rate 0% (0/1) · 1 confirmed · >=$3.25 spent (incomplete) · >=$3.25/confirmed"
        );
        assert_eq!(trend_json(&metrics)["providerSpendUnresolved"], true);
    }
}
