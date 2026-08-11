use std::cmp::Ordering;
use std::ops::Range;

use kuzushi_core::review_yield::domain::LeafKnowledgeGap;
pub(crate) use kuzushi_core::review_yield::domain::RankObjective;

use super::{compare_by_advisory_rate, compare_by_knowledge_gap};

/// One queue row reduced to everything the advisory comparators may look at.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ShadowRankRow {
    pub(crate) proof_rank: u8,
    pub(crate) severity_rank: u8,
    /// The advisory rate, present only for a fully eligible score.
    pub(crate) rate: Option<f64>,
    /// The knowledge-gap key, present only for a fully eligible score whose
    /// leaf reported both statistics.
    pub(crate) knowledge_gap: Option<LeafKnowledgeGap>,
    pub(crate) fingerprint: String,
}

impl ShadowRankRow {
    /// Whether this row carries the key `objective` ranks on. A row without it
    /// freezes its band rather than being ranked on a substitute.
    fn is_keyed_for(&self, objective: RankObjective) -> bool {
        match objective {
            RankObjective::Yield => self.rate.is_some(),
            RankObjective::Learn => self.knowledge_gap.is_some(),
        }
    }
}

/// The comparator each objective ranks a band with. The objective itself is a
/// core domain concept (a recorded session names it durably); only the ordering
/// it implies over shell rows lives here.
fn compare_for(objective: RankObjective, left: &ShadowRankRow, right: &ShadowRankRow) -> Ordering {
    match objective {
        RankObjective::Yield => compare_by_advisory_rate(left, right),
        RankObjective::Learn => compare_by_knowledge_gap(left, right),
    }
}

/// The advisory order, as baseline indices.
///
/// Proof band first, then severity — the same two keys the visible queue sorts
/// on — and only inside a band does `objective` move anything. The sort is
/// stable, so a band that does not reorder keeps its baseline sequence.
pub(crate) fn shadow_ranked_order(rows: &[ShadowRankRow], objective: RankObjective) -> Vec<usize> {
    let mut order: Vec<usize> = (0..rows.len()).collect();
    order.sort_by_key(|&index| band_key(&rows[index]));
    for band in band_ranges(rows, &order) {
        sort_band(rows, &mut order[band], objective);
    }
    order
}

/// Whether `objective` actually ranks any band of this queue.
///
/// False when every band is frozen or holds one row: the list on screen is
/// then the baseline in all but name, and no chrome may claim the model
/// ordered it.
pub(crate) fn ranks_any_band(rows: &[ShadowRankRow], objective: RankObjective) -> bool {
    let mut order: Vec<usize> = (0..rows.len()).collect();
    order.sort_by_key(|&index| band_key(&rows[index]));
    band_ranges(rows, &order)
        .into_iter()
        .any(|band| band.len() > 1 && band_is_rankable(rows, &order[band], objective))
}

fn band_key(row: &ShadowRankRow) -> (u8, u8) {
    (row.proof_rank, row.severity_rank)
}

/// The band-key runs of an already band-sorted `order`, as ranges into it.
fn band_ranges(rows: &[ShadowRankRow], order: &[usize]) -> Vec<Range<usize>> {
    let mut ranges = Vec::new();
    let mut start = 0;
    while start < order.len() {
        let end = band_end(rows, order, start);
        ranges.push(start..end);
        start = end;
    }
    ranges
}

fn band_end(rows: &[ShadowRankRow], order: &[usize], start: usize) -> usize {
    let key = band_key(&rows[order[start]]);
    order[start..]
        .iter()
        .position(|&index| band_key(&rows[index]) != key)
        .map_or(order.len(), |offset| start + offset)
}

/// A band reorders only when every row in it carries the objective's key.
/// Ranking a keyed row against an unkeyed one would assert a comparison the
/// evidence does not support, so a partially keyed band keeps baseline order.
fn sort_band(rows: &[ShadowRankRow], band: &mut [usize], objective: RankObjective) {
    if !band_is_rankable(rows, band, objective) {
        return;
    }
    band.sort_by(|&left, &right| compare_for(objective, &rows[left], &rows[right]));
}

fn band_is_rankable(rows: &[ShadowRankRow], band: &[usize], objective: RankObjective) -> bool {
    band.iter()
        .all(|&index| rows[index].is_keyed_for(objective))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(proof: u8, severity: u8, rate: Option<f64>, fingerprint: &str) -> ShadowRankRow {
        ShadowRankRow {
            proof_rank: proof,
            severity_rank: severity,
            rate,
            knowledge_gap: rate.map(|_| gap(0.5, 10)),
            fingerprint: fingerprint.to_string(),
        }
    }

    fn gap(entropy_bits: f64, support: u32) -> LeafKnowledgeGap {
        LeafKnowledgeGap {
            entropy_bits,
            support,
        }
    }

    /// A row keyed for Learn only, so a Learn assertion cannot pass by
    /// accidentally agreeing with the yield key.
    fn learn_row(
        proof: u8,
        severity: u8,
        knowledge_gap: Option<LeafKnowledgeGap>,
        fingerprint: &str,
    ) -> ShadowRankRow {
        ShadowRankRow {
            proof_rank: proof,
            severity_rank: severity,
            rate: None,
            knowledge_gap,
            fingerprint: fingerprint.to_string(),
        }
    }

    fn shadow_ranked_order(rows: &[ShadowRankRow]) -> Vec<usize> {
        super::shadow_ranked_order(rows, RankObjective::Yield)
    }

    #[test]
    fn shadow_rank_is_deterministic_and_1_based() {
        let rows = vec![
            row(1, 1, Some(0.10), "aaa"),
            row(1, 1, Some(0.90), "bbb"),
            row(1, 1, Some(0.50), "ccc"),
        ];

        let order = shadow_ranked_order(&rows);

        assert_eq!(order, vec![1, 2, 0]);
        assert_eq!(shadow_ranked_order(&rows), order);
        let rank = order.iter().position(|&index| index == 1).unwrap() + 1;
        assert_eq!(rank, 1);
    }

    #[test]
    fn ineligible_row_keeps_band_in_baseline_order() {
        let rows = vec![
            row(1, 1, Some(0.10), "aaa"),
            row(1, 1, None, "bbb"),
            row(1, 1, Some(0.90), "ccc"),
        ];

        assert_eq!(shadow_ranked_order(&rows), vec![0, 1, 2]);
    }

    #[test]
    fn a_fully_scored_band_reorders_without_disturbing_another_band() {
        let rows = vec![
            row(2, 0, Some(0.10), "aaa"),
            row(1, 0, None, "bbb"),
            row(2, 0, Some(0.90), "ccc"),
            row(1, 0, Some(0.99), "ddd"),
        ];

        // The proof-1 band is partially scored and holds baseline order; the
        // proof-2 band is complete and sorts by rate.
        assert_eq!(shadow_ranked_order(&rows), vec![1, 3, 2, 0]);
    }

    #[test]
    fn equal_rates_break_ties_on_fingerprint() {
        let rows = vec![row(0, 0, Some(0.5), "zzz"), row(0, 0, Some(0.5), "aaa")];

        assert_eq!(shadow_ranked_order(&rows), vec![1, 0]);
    }

    #[test]
    fn an_empty_queue_ranks_nothing() {
        assert!(shadow_ranked_order(&[]).is_empty());
    }

    /// The Learn key: widest knowledge gap first. Entropy leads, because a
    /// mixed leaf is what the model is least sure of.
    #[test]
    fn learn_orders_by_leaf_entropy_descending() {
        let rows = vec![
            learn_row(1, 1, Some(gap(0.10, 40)), "aaa"),
            learn_row(1, 1, Some(gap(0.99, 40)), "bbb"),
            learn_row(1, 1, Some(gap(0.50, 40)), "ccc"),
        ];

        assert_eq!(
            super::shadow_ranked_order(&rows, RankObjective::Learn),
            vec![1, 2, 0]
        );
    }

    /// Equal entropy: the leaf with fewer prior examples first. Both are above
    /// the model's evidence floor — a row below it never reaches this key.
    #[test]
    fn learn_breaks_entropy_ties_on_lower_support_first() {
        let rows = vec![
            learn_row(1, 1, Some(gap(0.80, 60)), "aaa"),
            learn_row(1, 1, Some(gap(0.80, 25)), "bbb"),
        ];

        assert_eq!(
            super::shadow_ranked_order(&rows, RankObjective::Learn),
            vec![1, 0]
        );
    }

    /// A full tie falls through to the baseline tie-break, so two identical
    /// leaves order the same way on every frame.
    #[test]
    fn learn_full_ties_keep_the_fingerprint_order() {
        let rows = vec![
            learn_row(1, 1, Some(gap(0.80, 25)), "zzz"),
            learn_row(1, 1, Some(gap(0.80, 25)), "aaa"),
        ];

        assert_eq!(
            super::shadow_ranked_order(&rows, RankObjective::Learn),
            vec![1, 0]
        );
    }

    /// The all-or-nothing rule is the objective's, not the yield key's: a row
    /// whose leaf withheld its statistics freezes the whole band.
    #[test]
    fn a_row_without_a_knowledge_gap_freezes_its_learn_band() {
        let rows = vec![
            learn_row(1, 1, Some(gap(0.10, 40)), "aaa"),
            learn_row(1, 1, None, "bbb"),
            learn_row(1, 1, Some(gap(0.99, 40)), "ccc"),
        ];

        assert_eq!(
            super::shadow_ranked_order(&rows, RankObjective::Learn),
            vec![0, 1, 2]
        );
    }

    /// A high-gap row in a weaker band stays below a zero-gap row in a
    /// stronger one. Learn never crosses a band, exactly like yield.
    #[test]
    fn learn_never_crosses_a_proof_or_severity_band() {
        let rows = vec![
            learn_row(2, 1, Some(gap(1.0, 20)), "aaa"),
            learn_row(1, 0, Some(gap(0.0, 90)), "bbb"),
        ];

        assert_eq!(
            super::shadow_ranked_order(&rows, RankObjective::Learn),
            vec![1, 0]
        );
    }

    /// The chrome predicate. A band that cannot be ranked leaves the queue in
    /// baseline order, and the indicator must not claim otherwise.
    #[test]
    fn ranks_any_band_is_false_for_frozen_and_single_row_bands() {
        let frozen = vec![
            learn_row(1, 1, Some(gap(0.10, 40)), "aaa"),
            learn_row(1, 1, None, "bbb"),
        ];
        let alone = vec![
            learn_row(1, 1, Some(gap(0.10, 40)), "aaa"),
            learn_row(2, 1, Some(gap(0.90, 40)), "bbb"),
        ];
        let ranked = vec![
            learn_row(1, 1, Some(gap(0.10, 40)), "aaa"),
            learn_row(1, 1, Some(gap(0.90, 40)), "bbb"),
        ];

        assert!(!ranks_any_band(&frozen, RankObjective::Learn));
        assert!(!ranks_any_band(&alone, RankObjective::Learn));
        assert!(ranks_any_band(&ranked, RankObjective::Learn));
    }
}
