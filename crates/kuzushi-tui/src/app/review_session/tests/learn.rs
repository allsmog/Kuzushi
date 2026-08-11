//! The Learn-mode ordering invariants.
//!
//! Learn changes one thing about `within-band`: the key a complete band is
//! ranked by. Everything a reordering could get wrong — crossing a band,
//! ranking against evidence that is not there, drifting between frames,
//! surviving a rollback — is pinned here again on the new key, because a
//! shared comparator is only shared until someone changes one branch of it.

use super::within_band::{
    armed_banded_harness, band_sequence, banded_harness, display_aliases, eligible_leaf,
    publish_score_row, rows_by_band, score_without_knowledge_gap, NON_ORDERING_MODES,
};
use super::*;
use crate::ui_view_models::{
    review_queue_model, LEARN_ORDERING_INDICATOR, REVIEW_YIELD_LEARN_CONTEXT,
};
use kuzushi_core::review_yield::application::ShadowQueueScore;
use kuzushi_core::ReviewYieldMode;

/// Entropy per queue row, chosen so the three-row High band must reorder and
/// the two-row Medium band must not: the Medium pair is already widest-first.
///
/// Support is held constant here so entropy alone explains the movement.
const MIXED_ENTROPY: [f64; 5] = [0.20, 0.95, 0.55, 0.90, 0.30];

fn learn_scores(entropy: &[f64]) -> Vec<Option<ShadowQueueScore>> {
    entropy
        .iter()
        .map(|bits| Some(eligible_leaf(0.5, *bits, 20, 20)))
        .collect()
}

fn publish_learn_scores(app: &mut ShellApp, entropy: &[f64]) {
    publish_score_row(app, learn_scores(entropy));
}

/// The headline promise: a fully scored band sorts by knowledge gap, and the
/// band structure of the list is untouched.
#[test]
fn learn_orders_inside_a_band_and_never_across_one() {
    let mut harness = armed_banded_harness(ReviewYieldMode::Learn);
    let baseline = display_aliases(&harness.app);
    let baseline_bands = band_sequence(&harness.app);

    publish_learn_scores(&mut harness.app, &MIXED_ENTROPY);
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

/// The widest gap leads. Entropy descending is the whole point of the mode:
/// the leaf whose prior outcomes were most mixed is the one a verdict teaches
/// the model the most about.
#[test]
fn the_highest_entropy_row_of_a_band_comes_first() {
    let mut harness = armed_banded_harness(ReviewYieldMode::Learn);

    publish_learn_scores(&mut harness.app, &MIXED_ENTROPY);

    let ordered = display_aliases(&harness.app);
    let baseline = display_aliases(&banded_harness().app);
    // Index 1 holds 0.95 bits, the widest gap in the three-row High band.
    assert_eq!(ordered[0], baseline[1]);
}

/// Equal entropy, unequal support: the leaf resting on fewer prior examples
/// goes first. Both are above the artifact's evidence floor — a row below it
/// never reaches this key.
#[test]
fn equal_entropy_puts_the_thinner_support_first() {
    let mut harness = armed_banded_harness(ReviewYieldMode::Learn);
    let baseline = display_aliases(&harness.app);

    publish_score_row(
        &mut harness.app,
        vec![
            Some(eligible_leaf(0.5, 0.80, 30, 30)),
            Some(eligible_leaf(0.5, 0.80, 12, 13)),
            Some(eligible_leaf(0.5, 0.80, 20, 20)),
            Some(eligible_leaf(0.5, 0.10, 20, 20)),
            Some(eligible_leaf(0.5, 0.10, 20, 20)),
        ],
    );

    let ordered = display_aliases(&harness.app);
    assert_eq!(
        &ordered[..3],
        &[
            baseline[1].clone(),
            baseline[2].clone(),
            baseline[0].clone()
        ],
        "support ascending inside one entropy tier"
    );
}

/// A full tie falls through to the baseline order, so a band the model cannot
/// distinguish looks exactly as it did before the model was armed.
#[test]
fn identical_leaves_keep_the_baseline_order() {
    let mut harness = armed_banded_harness(ReviewYieldMode::Learn);
    let baseline = display_aliases(&harness.app);

    publish_learn_scores(&mut harness.app, &[0.6; 5]);

    assert_eq!(display_aliases(&harness.app), baseline);
}

/// One row whose leaf withheld its statistics freezes the whole band, even
/// though every row in it is eligible and carries a rate. The freeze follows
/// the objective's own key, not a shared notion of "scored".
#[test]
fn a_row_without_a_knowledge_gap_freezes_its_entire_band() {
    for frozen in 0..3 {
        let mut harness = armed_banded_harness(ReviewYieldMode::Learn);
        let baseline = display_aliases(&harness.app);

        let mut scores = learn_scores(&MIXED_ENTROPY);
        scores[frozen] = Some(score_without_knowledge_gap(0.5));
        publish_score_row(&mut harness.app, scores);

        assert_eq!(
            display_aliases(&harness.app)[..3],
            baseline[..3],
            "a leaf without statistics at {frozen} must freeze the whole first band"
        );
    }
}

/// An unscorable row freezes its band the same way it does under yield.
#[test]
fn an_unscored_row_freezes_its_entire_band() {
    let mut harness = armed_banded_harness(ReviewYieldMode::Learn);
    let baseline = display_aliases(&harness.app);

    let mut scores = learn_scores(&MIXED_ENTROPY);
    scores[2] = None;
    publish_score_row(&mut harness.app, scores);

    assert_eq!(display_aliases(&harness.app)[..3], baseline[..3]);
}

/// Rollback: every non-ordering mode returns the byte-identical baseline list,
/// with the Learn score cache still populated.
#[test]
fn rollback_from_learn_restores_the_byte_identical_baseline() {
    let mut harness = armed_banded_harness(ReviewYieldMode::Learn);
    let baseline = display_aliases(&harness.app);
    publish_learn_scores(&mut harness.app, &MIXED_ENTROPY);
    assert_ne!(display_aliases(&harness.app), baseline);

    for mode in NON_ORDERING_MODES {
        arm_from_config(&mut harness.app, mode, shadow_model_path());
        publish_learn_scores(&mut harness.app, &MIXED_ENTROPY);

        assert_eq!(display_aliases(&harness.app), baseline, "{mode:?}");
    }
}

/// A mode alone never moves a row: with no memoized scores the answer is the
/// baseline, which is also the fail-closed answer when no artifact loaded.
#[test]
fn learn_without_scores_is_the_baseline() {
    let baseline = display_aliases(&banded_harness().app);

    let harness = armed_banded_harness(ReviewYieldMode::Learn);

    assert_eq!(display_aliases(&harness.app), baseline);
}

/// The backlog preset promises worst-severity-first. Learn does not touch it,
/// exactly as no other mode does.
#[test]
fn the_backlog_preset_is_never_learn_ordered() {
    let mut harness = armed_banded_harness(ReviewYieldMode::Learn);
    harness.app.router.workbench_mut().review_mut().backlog = true;
    let backlog_baseline = display_aliases(&harness.app);

    publish_learn_scores(&mut harness.app, &MIXED_ENTROPY);

    assert_eq!(display_aliases(&harness.app), backlog_baseline);
}

/// A session record's `baseline_rank` stays the genuine counterfactual under
/// Learn too: the baseline projection never sees the ordering.
#[test]
fn the_baseline_projection_ignores_learn_ordering() {
    let mut harness = armed_banded_harness(ReviewYieldMode::Learn);
    let baseline = baseline_sorted_finding_alias_indices(&harness.app);

    publish_learn_scores(&mut harness.app, &MIXED_ENTROPY);

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
fn learn_ordering_is_stable_across_repeated_projections() {
    let mut harness = armed_banded_harness(ReviewYieldMode::Learn);
    publish_learn_scores(&mut harness.app, &MIXED_ENTROPY);

    let first = display_aliases(&harness.app);
    for _ in 0..5 {
        assert_eq!(display_aliases(&harness.app), first);
    }
}

/// The two objectives are genuinely different keys. Rates ascending against
/// entropy descending would coincide if either branch quietly read the other's
/// number.
#[test]
fn learn_and_within_band_order_the_same_scores_differently() {
    let scores = vec![
        Some(eligible_leaf(0.90, 0.10, 20, 20)),
        Some(eligible_leaf(0.50, 0.95, 20, 20)),
        Some(eligible_leaf(0.10, 0.55, 20, 20)),
        Some(eligible_leaf(0.80, 0.90, 20, 20)),
        Some(eligible_leaf(0.20, 0.30, 20, 20)),
    ];

    let mut yield_harness = armed_banded_harness(ReviewYieldMode::WithinBand);
    publish_score_row(&mut yield_harness.app, scores.clone());
    let mut learn_harness = armed_banded_harness(ReviewYieldMode::Learn);
    publish_score_row(&mut learn_harness.app, scores);

    assert_ne!(
        display_aliases(&yield_harness.app),
        display_aliases(&learn_harness.app)
    );
}

/// Property sweep over seeded eligibility, entropy, and support assignments.
///
/// A hand-picked case proves the comparator works on the shape someone
/// imagined. This proves the three invariants hold on shapes nobody did: the
/// band sequence is preserved, each band keeps exactly its own rows, and the
/// result is reproducible. The generator is the same inline LCG the yield
/// sweep uses, so every failure is replayable from its seed.
#[test]
fn property_learn_is_a_per_band_permutation() {
    let mut state: u64 = 0x1EA4_5EED_0000_0001;
    let mut next = move || {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        state >> 33
    };

    for case in 0..200 {
        let mut harness = armed_banded_harness(ReviewYieldMode::Learn);
        let baseline = display_aliases(&harness.app);
        let baseline_bands = band_sequence(&harness.app);

        let scores: Vec<Option<ShadowQueueScore>> = (0..harness.app.findings().len())
            .map(|_| {
                let draw = next();
                // One row in four carries no Learn key, so frozen and fully
                // ranked bands both occur across the sweep.
                (draw % 4 != 0).then(|| {
                    let bits = (draw % 101) as f64 / 100.0;
                    let support = (draw % 37) as u32 + 8;
                    eligible_leaf(0.5, bits, support, support)
                })
            })
            .collect();
        publish_score_row(&mut harness.app, scores);

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
        assert_eq!(
            rows_by_band(&harness.app, &ordered),
            rows_by_band(&harness.app, &baseline),
            "case {case}: a band's membership changed"
        );
    }
}

// ── honest labeling ─────────────────────────────────────────────────────────

/// Copy that would recast a *model* knowledge gap as doubt about the finding
/// itself. "low confidence" additionally collides with the proof-confidence
/// vocabulary the same screen uses for something else entirely.
const BANNED_PHRASINGS: [&str; 6] = [
    "uncertain finding",
    "likely vulnerable",
    "low confidence",
    "risky",
    "unsure whether",
    "may be exploitable",
];

fn queue_indicator(app: &ShellApp) -> Option<&'static str> {
    review_queue_model(app, ReviewQueueMode::All).ordering_indicator
}

/// The chip states one thing, and it is true exactly when Learn is ranking a
/// band of the queue on screen.
#[test]
fn learn_shows_the_model_knowledge_gap_indicator_once_it_ranks_a_band() {
    let mut harness = armed_banded_harness(ReviewYieldMode::Learn);
    assert_eq!(
        queue_indicator(&harness.app),
        None,
        "an armed mode that has not scored anything ranks nothing"
    );

    publish_learn_scores(&mut harness.app, &MIXED_ENTROPY);

    assert_eq!(
        queue_indicator(&harness.app),
        Some(LEARN_ORDERING_INDICATOR)
    );
    assert!(LEARN_ORDERING_INDICATOR.contains("model knowledge-gap"));
}

/// The one state most likely to produce a lie: armed, scored, and yet every
/// band frozen, so the list on screen is the baseline.
#[test]
fn a_fully_frozen_queue_shows_no_indicator() {
    let mut harness = armed_banded_harness(ReviewYieldMode::Learn);
    let baseline = display_aliases(&harness.app);

    publish_score_row(&mut harness.app, vec![None, None, None, None, None]);

    assert_eq!(display_aliases(&harness.app), baseline);
    assert_eq!(queue_indicator(&harness.app), None);
}

/// No other mode may borrow the chip — including `within-band`, which orders
/// the queue by a different key and would be misdescribed by this one.
#[test]
fn no_other_mode_shows_the_learn_indicator() {
    for mode in [
        ReviewYieldMode::Off,
        ReviewYieldMode::Shadow,
        ReviewYieldMode::Visible,
        ReviewYieldMode::WithinBand,
    ] {
        let mut harness = armed_banded_harness(mode);
        publish_learn_scores(&mut harness.app, &MIXED_ENTROPY);

        assert_eq!(queue_indicator(&harness.app), None, "{mode:?}");
    }
}

/// The backlog preset is never model-ordered, so it never carries the chip
/// either — a signifier for an ordering that is not happening.
#[test]
fn the_backlog_projection_shows_no_indicator() {
    let mut harness = armed_banded_harness(ReviewYieldMode::Learn);
    harness.app.router.workbench_mut().review_mut().backlog = true;

    publish_learn_scores(&mut harness.app, &MIXED_ENTROPY);

    assert_eq!(queue_indicator(&harness.app), None);
}

/// Plain output is the scripted shell's only view: the chip has to survive it
/// verbatim, with no ANSI or box-drawing dependence.
#[test]
fn plain_output_carries_the_indicator_verbatim() {
    let mut harness = armed_banded_harness(ReviewYieldMode::Learn);
    let before = crate::renderer::render_plain_app(&harness.app, 120);
    assert!(!before.contains(LEARN_ORDERING_INDICATOR), "{before}");

    publish_learn_scores(&mut harness.app, &MIXED_ENTROPY);

    let plain = crate::renderer::render_plain_app(&harness.app, 120);
    assert!(plain.contains(LEARN_ORDERING_INDICATOR), "{plain}");
}

/// The detail's Learn line appears with the ordering and never without it, so
/// the two surfaces cannot disagree about whether Learn is moving rows.
#[test]
fn the_detail_learn_context_tracks_the_same_state_as_the_indicator() {
    let mut harness = armed_banded_harness(ReviewYieldMode::Learn);
    publish_learn_scores(&mut harness.app, &MIXED_ENTROPY);
    let finding = harness.app.findings()[0].clone();

    let signal = learn_signal_view(&harness.app, &finding);
    assert_eq!(signal.learn_context, Some(REVIEW_YIELD_LEARN_CONTEXT));

    arm_from_config(
        &mut harness.app,
        ReviewYieldMode::Visible,
        shadow_model_path(),
    );
    publish_learn_scores(&mut harness.app, &MIXED_ENTROPY);

    assert_eq!(
        learn_signal_view(&harness.app, &finding).learn_context,
        None,
        "visible mode orders nothing, so it explains no ordering"
    );
}

/// The signal view for a finding whose leaf is fully populated. The harness's
/// findings have no durable identity, so the score is published directly.
fn learn_signal_view(
    app: &ShellApp,
    finding: &Finding,
) -> crate::ui_view_models::ReviewYieldSignalViewModel {
    match review_yield_detail_for(app, finding).expect("an ordering mode always attaches a section")
    {
        ReviewYieldDetailModel::Signal(signal) => signal,
        ReviewYieldDetailModel::Unavailable { message } => {
            panic!("expected a scored leaf, got: {message}")
        }
    }
}

/// Every rendered Learn surface, run through the operator-copy lints and the
/// vulnerability-uncertainty deny-list at once. A phrase that recast the
/// model's gap as doubt about the finding would be the one dishonest thing
/// this mode could say.
#[test]
fn every_rendered_learn_surface_is_lint_clean_and_never_claims_vulnerability_doubt() {
    let mut harness = armed_banded_harness(ReviewYieldMode::Learn);
    publish_learn_scores(&mut harness.app, &MIXED_ENTROPY);
    harness.app.open_finding_at_cursor();

    let mut corpus = Vec::new();
    for width in [80usize, 120, 160] {
        let rendered = crate::renderer::render_plain_app(&harness.app, width);
        for (index, text) in rendered.lines().enumerate() {
            corpus.push(crate::renderer::surface_lints::SurfaceLine {
                source: format!("plain:learn:{width}"),
                number: index + 1,
                text: text.to_string(),
            });
        }
    }
    assert!(
        corpus
            .iter()
            .any(|line| line.text.contains("knowledge-gap")),
        "the Learn chrome must be in the corpus it is linted against"
    );

    let violations = crate::renderer::surface_lints::lint_jargon(&corpus);
    assert!(
        violations.is_empty(),
        "{}",
        violations
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    );
    for line in &corpus {
        let lowered = line.text.to_ascii_lowercase();
        for banned in BANNED_PHRASINGS {
            assert!(!lowered.contains(banned), "{banned} in {}", line.text);
        }
    }
    assert!(
        REVIEW_YIELD_LEARN_CONTEXT.contains("the model has least evidence about"),
        "the gap named must be the model's"
    );
}

// ------------------------------------------------------- what the record says

/// Scores whose yield order and learn order disagree, so a record that ranked
/// by the wrong objective is visible as a different number rather than as a
/// coincidence.
const DISAGREEING_SCORES: [(f64, f64); 5] = [
    (0.90, 0.10),
    (0.50, 0.90),
    (0.10, 0.50),
    (0.50, 0.50),
    (0.40, 0.40),
];

fn disagreeing_scores(app: &ShellApp) -> HashMap<String, ShadowQueueScore> {
    app.findings()
        .iter()
        .zip(DISAGREEING_SCORES)
        .map(|(finding, (rate, entropy))| {
            (
                finding_stable_fp(finding).to_string(),
                eligible_leaf(rate, entropy, 20, 20),
            )
        })
        .collect()
}

fn recorded_write(mode: ReviewYieldMode) -> ReviewSessionWrite {
    let mut harness = armed_banded_harness(mode);
    let scores = disagreeing_scores(&harness.app);
    let effects = harness.app.open_finding_at_cursor();
    let apply = one_session_start(&effects);
    let model = harness.app.runtime_state.review_yield().model().unwrap();
    review_session_write(apply, &model, &scores)
}

/// A learn session records where the learn ordering put the row, labelled as
/// such. Recording the yield position under a learn session would answer a
/// question the operator was never shown.
#[test]
fn a_learn_session_records_the_learn_rank_and_names_it() {
    let write = recorded_write(ReviewYieldMode::Learn);

    assert_eq!(write.baseline_rank, 1);
    assert_eq!(write.shadow_rank, Some(3), "the widest gap leads");
    assert_eq!(write.shadow_rank_objective, Some(RankObjective::Learn));
}

/// The yield-ordering mode records the yield position under its own label, so
/// two sessions with the same number always mean the same thing.
#[test]
fn a_within_band_session_records_the_yield_rank_and_names_it() {
    let write = recorded_write(ReviewYieldMode::WithinBand);

    assert_eq!(write.shadow_rank, Some(1), "the highest rate leads");
    assert_eq!(write.shadow_rank_objective, Some(RankObjective::Yield));
}

/// A mode that orders nothing still records the prospective yield position —
/// and says so, rather than leaving the number's key to be guessed.
#[test]
fn a_shadow_session_records_the_yield_rank_and_names_it() {
    let write = recorded_write(ReviewYieldMode::Shadow);

    assert_eq!(write.shadow_rank, Some(1));
    assert_eq!(write.shadow_rank_objective, Some(RankObjective::Yield));
}

/// An unranked row names no objective: a label without a number would claim a
/// measurement that was never taken.
#[test]
fn an_unranked_session_records_no_objective() {
    let mut harness = armed_banded_harness(ReviewYieldMode::Learn);
    let effects = harness.app.open_finding_at_cursor();
    let apply = one_session_start(&effects);
    let model = harness.app.runtime_state.review_yield().model().unwrap();

    let write = review_session_write(apply, &model, &HashMap::new());

    assert_eq!(write.shadow_rank, None);
    assert_eq!(write.shadow_rank_objective, None);
}
