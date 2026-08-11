//! The within-band ordering invariants.
//!
//! Reordering a security review queue is the one thing in this feature that
//! can hurt an operator: a row that moves out of its proof or severity band
//! misrepresents how much is known about it. Every test here pins a way that
//! must not happen.

use super::*;
use kuzushi_core::review_yield::application::{ShadowQueueScore, UnscorableReason};
use kuzushi_core::review_yield::domain::{
    severity_rank, ReviewYieldEligibility, ReviewYieldSignal,
};
use kuzushi_core::ProofConfidence;
use std::collections::HashMap;

/// Every mode a rollback can land on. Any of these must restore the baseline
/// list byte for byte, even with a full score cache in hand.
pub(super) const NON_ORDERING_MODES: [ReviewYieldMode; 3] = [
    ReviewYieldMode::Off,
    ReviewYieldMode::Shadow,
    ReviewYieldMode::Visible,
];

/// Rates chosen so the first band must reorder and the second must not, which
/// makes "ordering happened" and "ordering stayed put" both observable in one
/// projection.
const MIXED_RATES: [Option<f64>; 5] = [Some(0.10), Some(0.50), Some(0.90), Some(0.80), Some(0.20)];

fn eligible_score(rate: f64) -> ShadowQueueScore {
    eligible_leaf(rate, 0.72, 8, 2)
}

/// One eligible leaf, with every number the two ordering keys read: the rate
/// the yield key ranks on, and the entropy and outcome counts the Learn key
/// ranks on.
pub(super) fn eligible_leaf(
    rate: f64,
    entropy_bits: f64,
    positive: u32,
    negative: u32,
) -> ShadowQueueScore {
    ShadowQueueScore::Scored {
        signal: ReviewYieldSignal {
            model_id: "review-tree-v1".to_string(),
            task_id: "review-yield".to_string(),
            feature_schema_id: "test".to_string(),
            leaf_id: Some(1),
            smoothed_positive_rate: Some(rate),
            credible_interval_95: Some((rate, rate)),
            positive_count: Some(positive),
            negative_count: Some(negative),
            leaf_entropy_bits: Some(entropy_bits),
            decision_path: Vec::new(),
            eligibility: ReviewYieldEligibility::Eligible,
        },
        feature_snapshot_hash: "snapshot".to_string(),
    }
}

/// An eligible score whose leaf withheld its statistics: rankable by yield,
/// unrankable by Learn. It is what proves the two objectives freeze a band on
/// their own key rather than on a shared one.
pub(super) fn score_without_knowledge_gap(rate: f64) -> ShadowQueueScore {
    let ShadowQueueScore::Scored {
        mut signal,
        feature_snapshot_hash,
    } = eligible_leaf(rate, 0.5, 8, 2)
    else {
        unreachable!("eligible_leaf builds a scored row")
    };
    signal.leaf_entropy_bits = None;
    ShadowQueueScore::Scored {
        signal,
        feature_snapshot_hash,
    }
}

/// Publishes an explicit score per queue row, the way a completed scoring
/// effect does.
pub(super) fn publish_score_row(app: &mut ShellApp, scores: Vec<Option<ShadowQueueScore>>) {
    let by_stable_fp: HashMap<String, ShadowQueueScore> = app
        .findings()
        .iter()
        .map(|finding| finding_stable_fp(finding).to_string())
        .zip(scores)
        .map(|(fp, score)| {
            (
                fp,
                score.unwrap_or(ShadowQueueScore::Unscorable(
                    UnscorableReason::NoDurableIdentity,
                )),
            )
        })
        .collect();
    let revision = app.findings_revision();
    let cutoff = app
        .findings_read_watermark()
        .expect("the harness sets a read cutoff");
    app.runtime_state
        .review_yield_mut()
        .store_scores(revision, cutoff, by_stable_fp);
}

/// Publishes scores the way a completed scoring effect does, so the ordering
/// path reads the same memoized cache it reads in production.
pub(super) fn publish_scores(app: &mut ShellApp, rates: &[Option<f64>]) {
    let by_stable_fp: HashMap<String, ShadowQueueScore> = app
        .findings()
        .iter()
        .map(|finding| finding_stable_fp(finding).to_string())
        .zip(rates.iter())
        .map(|(fp, rate)| {
            let score = rate.map_or_else(
                || ShadowQueueScore::Unscorable(UnscorableReason::NoDurableIdentity),
                eligible_score,
            );
            (fp, score)
        })
        .collect();
    let revision = app.findings_revision();
    let cutoff = app
        .findings_read_watermark()
        .expect("the harness sets a read cutoff");
    app.runtime_state
        .review_yield_mut()
        .store_scores(revision, cutoff, by_stable_fp);
}

pub(super) fn display_aliases(app: &ShellApp) -> Vec<String> {
    visible_sorted_finding_alias_indices(app)
        .into_iter()
        .map(|(alias, _)| alias)
        .collect()
}

/// The sequence of (proof, severity) bands walking down the displayed list.
/// Identical before and after ordering means no row crossed a band.
pub(super) fn band_sequence(app: &ShellApp) -> Vec<(u8, u8)> {
    visible_sorted_finding_alias_indices(app)
        .into_iter()
        .filter_map(|(_, index)| app.findings().get(index))
        .map(|finding| {
            (
                ProofConfidence::classify(finding).rank(),
                severity_rank(finding.severity),
            )
        })
        .collect()
}

/// A queue spanning two severity bands, so a comparator that ignored bands
/// would visibly interleave them.
pub(super) fn banded_harness() -> Harness {
    let mut harness = harness(0);
    harness.app.set_findings(
        [
            Severity::High,
            Severity::High,
            Severity::High,
            Severity::Medium,
            Severity::Medium,
        ]
        .into_iter()
        .enumerate()
        .map(|(index, severity)| queue_finding(index, severity))
        .collect(),
    );
    harness.app.set_findings_read_watermark(Some(12_000));
    harness
}

pub(super) fn armed_banded_harness(mode: ReviewYieldMode) -> Harness {
    let mut harness = banded_harness();
    arm_from_config(&mut harness.app, mode, shadow_model_path());
    harness
}

/// The headline promise: a fully scored band sorts by advisory rate, and the
/// band structure of the list is untouched.
#[test]
fn within_band_orders_inside_a_band_and_never_across_one() {
    let mut harness = armed_banded_harness(ReviewYieldMode::WithinBand);
    let baseline = display_aliases(&harness.app);
    let baseline_bands = band_sequence(&harness.app);

    publish_scores(&mut harness.app, &MIXED_RATES);
    let ordered = display_aliases(&harness.app);

    assert_ne!(ordered, baseline, "a fully scored band must reorder");
    assert_eq!(
        band_sequence(&harness.app),
        baseline_bands,
        "no row may cross a proof or severity band"
    );
    let mut before = baseline;
    let mut after = ordered;
    before.sort();
    after.sort();
    assert_eq!(before, after, "ordering is a permutation, never a filter");
}

/// One unscored row freezes its whole band. Ranking a scored row against an
/// unscored one would assert a comparison the evidence does not support, and
/// nothing on screen would tell the operator which half was guessed.
#[test]
fn one_ineligible_row_freezes_its_entire_band() {
    for frozen in 0..3 {
        let mut harness = armed_banded_harness(ReviewYieldMode::WithinBand);
        let baseline = display_aliases(&harness.app);

        let mut rates = MIXED_RATES.to_vec();
        rates[frozen] = None;
        publish_scores(&mut harness.app, &rates);

        assert_eq!(
            display_aliases(&harness.app)[..3],
            baseline[..3],
            "an unscored row at {frozen} must freeze the whole first band"
        );
    }
}

/// Rollback: returning to any non-ordering mode returns the byte-identical
/// baseline list, with the score cache still populated.
#[test]
fn non_ordering_modes_restore_the_byte_identical_baseline() {
    let mut harness = armed_banded_harness(ReviewYieldMode::WithinBand);
    let baseline = display_aliases(&harness.app);
    publish_scores(&mut harness.app, &MIXED_RATES);
    assert_ne!(display_aliases(&harness.app), baseline);

    for mode in NON_ORDERING_MODES {
        arm_from_config(&mut harness.app, mode, shadow_model_path());
        publish_scores(&mut harness.app, &MIXED_RATES);

        assert_eq!(display_aliases(&harness.app), baseline, "{mode:?}");
    }
}

/// A mode alone never moves a row. With no memoized scores the answer is the
/// baseline, not an ordering over whatever happens to be cached.
#[test]
fn within_band_without_scores_is_the_baseline() {
    let baseline = display_aliases(&banded_harness().app);

    let harness = armed_banded_harness(ReviewYieldMode::WithinBand);

    assert_eq!(display_aliases(&harness.app), baseline);
}

/// The backlog preset promises worst-severity-first. Review yield never
/// touches it, in any mode — including the one that orders.
#[test]
fn the_backlog_preset_is_never_model_ordered() {
    let mut harness = armed_banded_harness(ReviewYieldMode::WithinBand);
    harness.app.router.workbench_mut().review_mut().backlog = true;
    let backlog_baseline = display_aliases(&harness.app);

    publish_scores(&mut harness.app, &MIXED_RATES);

    assert_eq!(display_aliases(&harness.app), backlog_baseline);
}

/// A session record's `baseline_rank` must stay the genuine counterfactual.
/// If it followed the displayed order it would agree with the advisory rank by
/// construction in this mode, destroying the comparison it exists to preserve.
#[test]
fn the_baseline_projection_ignores_within_band_ordering() {
    let mut harness = armed_banded_harness(ReviewYieldMode::WithinBand);
    let baseline = baseline_sorted_finding_alias_indices(&harness.app);

    publish_scores(&mut harness.app, &MIXED_RATES);

    assert_ne!(
        visible_sorted_finding_alias_indices(&harness.app),
        baseline,
        "the displayed order moved"
    );
    assert_eq!(
        baseline_sorted_finding_alias_indices(&harness.app),
        baseline,
        "the baseline projection did not"
    );
}

/// Equal inputs produce equal output, every time. An ordering that drifted
/// between frames would move a row under the operator's cursor.
#[test]
fn within_band_ordering_is_stable_across_repeated_projections() {
    let mut harness = armed_banded_harness(ReviewYieldMode::WithinBand);
    publish_scores(
        &mut harness.app,
        &[Some(0.5), Some(0.5), Some(0.5), Some(0.2), Some(0.2)],
    );

    let first = display_aliases(&harness.app);
    for _ in 0..5 {
        assert_eq!(display_aliases(&harness.app), first);
    }
}

/// Property sweep over seeded eligibility and rate assignments.
///
/// A hand-picked case proves the comparator works on the shape someone
/// imagined. This proves the three invariants hold on shapes nobody did: the
/// band sequence is preserved, each band keeps exactly its own rows, and the
/// result is reproducible. The generator is an inline LCG so the sweep adds no
/// dependency and every failure is replayable from its seed.
#[test]
fn property_within_band_is_a_per_band_permutation() {
    let mut state: u64 = 0x5EED_1234_ABCD_0001;
    let mut next = move || {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        state >> 33
    };

    for case in 0..200 {
        let mut harness = armed_banded_harness(ReviewYieldMode::WithinBand);
        let baseline = display_aliases(&harness.app);
        let baseline_bands = band_sequence(&harness.app);

        let rates: Vec<Option<f64>> = (0..harness.app.findings().len())
            .map(|_| {
                let draw = next();
                // One row in four is ineligible, so frozen and fully scored
                // bands both occur across the sweep.
                (draw % 4 != 0).then(|| (draw % 101) as f64 / 100.0)
            })
            .collect();
        publish_scores(&mut harness.app, &rates);

        let ordered = display_aliases(&harness.app);

        assert_eq!(
            band_sequence(&harness.app),
            baseline_bands,
            "case {case}: a row crossed a band"
        );
        let mut before = baseline.clone();
        let mut after = ordered.clone();
        before.sort();
        after.sort();
        assert_eq!(before, after, "case {case}: rows were added or dropped");
        assert_eq!(
            display_aliases(&harness.app),
            ordered,
            "case {case}: ordering was not reproducible"
        );

        // Per band, the multiset of rows is unchanged: ordering may permute
        // inside a band but may never move a row between two of them.
        assert_eq!(
            rows_by_band(&harness.app, &ordered),
            rows_by_band(&harness.app, &baseline),
            "case {case}: a band's membership changed"
        );
    }
}

/// Band key -> the sorted set of aliases in it. Sorted so the comparison is
/// about membership, not about the order this test is trying to allow.
pub(super) fn rows_by_band(app: &ShellApp, aliases: &[String]) -> Vec<((u8, u8), Vec<String>)> {
    let by_alias: HashMap<String, usize> = visible_sorted_finding_alias_indices(app)
        .into_iter()
        .collect();
    let mut bands: std::collections::BTreeMap<(u8, u8), Vec<String>> = Default::default();
    for alias in aliases {
        let Some(finding) = by_alias
            .get(alias)
            .and_then(|index| app.findings().get(*index))
        else {
            continue;
        };
        let key = (
            ProofConfidence::classify(finding).rank(),
            severity_rank(finding.severity),
        );
        bands.entry(key).or_default().push(alias.clone());
    }
    bands
        .into_iter()
        .map(|(key, mut aliases)| {
            aliases.sort();
            (key, aliases)
        })
        .collect()
}
