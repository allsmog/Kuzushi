//! What the loaded findings ledger attributes to one attempt's runs.
//!
//! A run reports how many findings it emitted; the ledger folds same-issue
//! observations into one finding. Both numbers are real and they disagree, so
//! every projection that names an attempt's findings has to agree on which one
//! it is naming. This module is the single place that reads the ledger for an
//! attempt, so the Scan page's delta pane and the RESULT READY banner above it
//! can never answer that question differently.

use super::ShellApp;
use std::collections::BTreeSet;

/// What the loaded ledger says about one attempt's runs: how many distinct
/// findings it attributes to them, and how those split across severity bands.
pub(crate) struct AttributedFindings {
    pub(crate) distinct: u64,
    /// Highest band first, zero buckets omitted.
    pub(crate) severity_counts: Vec<(String, u64)>,
}

/// The three finding facts one attempt's projection shows, derived together so
/// the count and the bands beneath it can never come from different evidence.
pub(crate) struct AttemptFindingFacts {
    pub(crate) count: Option<u64>,
    pub(crate) observed: Option<u64>,
    pub(crate) severity_counts: Vec<(String, u64)>,
}

impl ShellApp {
    /// Bucket the findings the ledger attributes to this attempt's runs,
    /// counting the total and the bands in one pass so a panel can never print
    /// one number as "findings" and break a different one down beside it.
    ///
    /// Attribution is `finding_observed_in_runs`, the shared source-aware rule:
    /// a finding re-observed by a later run keeps that run as its
    /// representative `scan_id` while the earlier run stays in `sources`, so
    /// matching the representative alone would drop the finding from the very
    /// attempt that found it — and then read the recorded count's excess as
    /// corroboration.
    ///
    /// `None` when the claim has no backing. A clamped ledger holds only part
    /// of the target's findings and a filtered one only the rows the operator
    /// asked to see, so in either case both numbers would be floors — a filter
    /// must never move what an accepted attempt found. An attempt the ledger
    /// attributes nothing to is the ordinary case of a summary whose findings
    /// were never projected, not an observed zero. Recorded finding deltas stay
    /// separate from the distinct count projected from the ledger.
    pub(crate) fn attributed_findings(&self, run_refs: &[String]) -> Option<AttributedFindings> {
        if self.findings_are_partial() || self.active_findings_filter().is_some() {
            return None;
        }
        let run_refs = run_refs.iter().cloned().collect::<BTreeSet<_>>();
        let mut counts = std::collections::BTreeMap::new();
        let mut distinct = 0_u64;
        for finding in self.findings() {
            if super::finding_observed_in_runs(finding, &run_refs) {
                distinct += 1;
                *counts.entry(finding.severity).or_insert(0u64) += 1;
            }
        }
        (distinct > 0).then(|| AttributedFindings {
            distinct,
            severity_counts: counts
                .into_iter()
                .rev()
                .map(|(severity, count)| (severity.as_str().to_string(), count))
                .collect(),
        })
    }

    /// `recorded` is what the attempt's runs reported emitting. The ledger
    /// folds same-issue observations into one finding, so a recorded count
    /// above the ledger's is that fold, not a second finding count: reporting
    /// it as the attempt's findings is what made the delta panel read
    /// `findings 27` beside its own `20 high · 5 medium` breakdown. It is
    /// disclosed only when it is the higher number, since nothing else would be
    /// a fold. Without ledger evidence the recorded count stands alone with no
    /// bands, which is all this projection ever knew.
    pub(crate) fn attempt_finding_facts(
        &self,
        run_refs: &[String],
        recorded: Option<u64>,
    ) -> AttemptFindingFacts {
        let Some(ledger) = self.attributed_findings(run_refs) else {
            return AttemptFindingFacts {
                count: recorded,
                observed: None,
                severity_counts: Vec::new(),
            };
        };
        AttemptFindingFacts {
            count: Some(ledger.distinct),
            observed: recorded.filter(|observations| *observations > ledger.distinct),
            severity_counts: ledger.severity_counts,
        }
    }
}

/// The recorded `added`/`updated` delta an attempt may present as a *finding*
/// delta. A producer counts its own delta in fingerprints; the ledger folds
/// same-issue observations into findings, so the moment the two disagree the
/// delta has stopped counting the findings the breakdown beside it describes.
///
/// Dropping it there leaves the projection with the reconciled
/// `distinct`/`observations` pair, which names both real numbers, instead of
/// printing `findings +31 added · 0 updated` above a `20 high · 5 medium ·
/// 4 low` breakdown of 29 (issue #172). A claim with no ledger count behind it
/// has nothing to contradict and keeps its delta.
pub(crate) fn finding_delta_in_ledger_unit(
    ledger_count: Option<u64>,
    added: u64,
    updated: u64,
) -> (Option<u64>, Option<u64>) {
    match ledger_count {
        Some(count) if added.saturating_add(updated) != count => (None, None),
        _ => (Some(added), Some(updated)),
    }
}

#[cfg(test)]
mod tests {
    use super::finding_delta_in_ledger_unit;

    #[test]
    fn a_delta_counting_the_ledgers_own_findings_is_presentable() {
        assert_eq!(
            finding_delta_in_ledger_unit(Some(6), 4, 2),
            (Some(4), Some(2))
        );
        assert_eq!(
            finding_delta_in_ledger_unit(Some(0), 0, 0),
            (Some(0), Some(0))
        );
    }

    /// Issue #172: `sast:scan` recorded a 31-fingerprint delta for runs the
    /// ledger attributes 29 findings to, and the panel printed `+31 added`
    /// above its own `20 high · 5 medium · 4 low` breakdown of those 29.
    #[test]
    fn a_delta_the_ledger_folded_is_no_longer_a_finding_delta() {
        assert_eq!(finding_delta_in_ledger_unit(Some(29), 31, 0), (None, None));
        assert_eq!(finding_delta_in_ledger_unit(Some(29), 20, 11), (None, None));
    }

    #[test]
    fn a_delta_with_no_ledger_count_behind_it_keeps_its_own_numbers() {
        assert_eq!(
            finding_delta_in_ledger_unit(None, 31, 0),
            (Some(31), Some(0))
        );
    }
}
