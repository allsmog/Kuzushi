use super::*;

fn path_step(feature: &str, taken: PathBranch) -> ReviewYieldPathStep {
    ReviewYieldPathStep {
        node_id: 3,
        feature: feature.to_string(),
        taken,
    }
}

/// A leaf the model committed to, with every statistic present.
fn eligible_signal() -> ReviewYieldSignal {
    ReviewYieldSignal {
        model_id: "blake3:18655b7ee138903ea277aeefbd926ec771f2a3c9024228302d99e86a5b61df10"
            .to_string(),
        task_id: "review-yield".to_string(),
        feature_schema_id: "features".to_string(),
        leaf_id: Some(7),
        smoothed_positive_rate: Some(0.74),
        credible_interval_95: Some((0.59, 0.85)),
        positive_count: Some(31),
        negative_count: Some(11),
        leaf_entropy_bits: Some(0.83),
        decision_path: vec![
            path_step(
                "static_proof",
                PathBranch::Branch {
                    value: "source_sink_linked".to_string(),
                },
            ),
            path_step("distinct_tools", PathBranch::Right { threshold: 1.0 }),
            path_step("reopened_count", PathBranch::Left { threshold: 2.5 }),
            path_step(
                "path_bucket",
                PathBranch::Missing {
                    direction: "left".to_string(),
                },
            ),
        ],
        eligibility: ReviewYieldEligibility::Eligible,
    }
}

fn signal_with(eligibility: ReviewYieldEligibility) -> ReviewYieldSignal {
    ReviewYieldSignal {
        eligibility,
        ..eligible_signal()
    }
}

fn view_of(signal: &ReviewYieldSignal) -> ReviewYieldSignalViewModel {
    match detail_for_signal(signal, None) {
        ReviewYieldDetailModel::Signal(view) => view,
        other => panic!("expected a signal, got {other:?}"),
    }
}

fn message_of(detail: &ReviewYieldDetailModel) -> &str {
    match detail {
        ReviewYieldDetailModel::Unavailable { message } => message,
        other => panic!("expected an unavailable state, got {other:?}"),
    }
}

/// Every number the operator reads is decided here, so every one of them is
/// pinned here too. A renderer that reformats one of these is changing what
/// the signal claims.
#[test]
fn eligible_signal_formats_rate_support_interval_entropy_and_path() {
    let view = view_of(&eligible_signal());

    assert_eq!(view.rate_label, "74%");
    assert_eq!(view.support_label, "42 (31 confirmed · 11 rejected)");
    assert_eq!(view.interval_label, "59%–85%");
    assert_eq!(view.entropy_label, "0.83 bits");
    assert_eq!(
        view.path_steps,
        vec![
            "static_proof = source_sink_linked".to_string(),
            "distinct_tools > 1".to_string(),
            "reopened_count ≤ 2.5".to_string(),
            "path_bucket absent, followed the left branch".to_string(),
        ]
    );
}

/// Every refusal names the fact that caused it. "Unavailable" alone would
/// leave an operator unable to tell a broken artifact from a finding the model
/// has never seen, and a blank would read as a rendering bug.
#[test]
fn each_ineligible_variant_yields_its_honest_message() {
    let cases = [
        (
            ReviewYieldEligibility::Disabled,
            "the signal is turned off for this session",
        ),
        (
            ReviewYieldEligibility::NoModelConfigured,
            "no model is configured — nothing was scored",
        ),
        (
            ReviewYieldEligibility::InvalidModelHash,
            "the model file failed its integrity check — signal unavailable",
        ),
        (
            ReviewYieldEligibility::UnsupportedModelSchema,
            "the model file format is not supported — signal unavailable",
        ),
        (
            ReviewYieldEligibility::FeatureSchemaMismatch,
            "the model expects a different set of inputs — signal unavailable",
        ),
        (
            ReviewYieldEligibility::MissingRequiredFeature {
                feature: "distinct_tools".to_string(),
            },
            "this finding lacks a required input (distinct_tools) — signal unavailable",
        ),
        (
            ReviewYieldEligibility::UnknownCategory {
                feature: "tool_family".to_string(),
                value: "novel".to_string(),
            },
            "tool_family is novel, which the model never saw in training — signal unavailable",
        ),
        (
            ReviewYieldEligibility::InsufficientLeafSupport { support: 3 },
            "only 3 prior reviewed examples match this finding, below this model's evidence floor — no rate is shown",
        ),
        (
            ReviewYieldEligibility::OutOfDistribution {
                reason: "depth guard exceeded".to_string(),
            },
            "this finding is outside the model's known data (depth guard exceeded) — signal unavailable",
        ),
    ];

    for (eligibility, expected) in cases {
        let detail = detail_for_signal(&signal_with(eligibility.clone()), None);
        assert_eq!(message_of(&detail), expected, "for {eligibility:?}");
    }
}

/// A thin leaf still carries statistics, but a headline percentage beside
/// three examples invites exactly the ranking use this feature refuses. The
/// count is stated instead.
#[test]
fn a_leaf_below_the_evidence_floor_states_the_count_and_shows_no_rate() {
    let detail = detail_for_signal(
        &signal_with(ReviewYieldEligibility::InsufficientLeafSupport { support: 3 }),
        None,
    );

    let message = message_of(&detail);
    assert!(
        message.contains("only 3 prior reviewed examples"),
        "{message}"
    );
    assert!(!message.contains('%'), "no rate may appear: {message}");
}

/// `Eligible` with a leaf that withheld a number is an artifact defect, not a
/// fact about the finding. Rendering the rate beside a blank interval would
/// read as a rendering bug.
#[test]
fn an_eligible_signal_missing_leaf_statistics_reports_an_incomplete_leaf() {
    let signal = ReviewYieldSignal {
        credible_interval_95: None,
        ..eligible_signal()
    };

    let detail = detail_for_signal(&signal, None);

    assert_eq!(
        message_of(&detail),
        "the model returned an incomplete leaf — signal unavailable"
    );
}

/// A row the model never saw is a different fact from one it declined to
/// score, so it gets its own wording.
#[test]
fn each_unscorable_reason_yields_its_own_message() {
    assert_eq!(
        unscorable_message(UnscorableReason::NoDurableIdentity),
        "this finding has no durable identity, so no review history joins to it"
    );
    assert_eq!(
        unscorable_message(UnscorableReason::NoStoredSnapshot),
        "no stored record of this finding exists yet — rescan the target to create one"
    );
    assert_eq!(
        unscorable_message(UnscorableReason::SnapshotUnreadable),
        "this finding's stored record could not be read — signal unavailable"
    );
}

/// A full digest is 71 unbreakable columns; a schema-version-shaped id reads
/// as a contract tag. Neither belongs on an operator surface, and neither may
/// be replaced by silence.
#[test]
fn model_label_clips_digests_and_defuses_schema_version_shaped_ids() {
    let digest = "blake3:18655b7ee138903ea277aeefbd926ec771f2a3c9024228302d99e86a5b61df10";
    let clipped = display_model_label(digest);
    assert_eq!(clipped, "blake3:18655b7ee138…");
    assert!(clipped.chars().count() < 40, "{clipped}");

    assert_eq!(display_model_label("review-tree-v1"), "review-tree (v1)");
    assert_eq!(display_model_label("review-tree"), "review-tree");
    // A short non-digest value after the colon is not a hash to clip.
    assert_eq!(display_model_label("name:abc"), "name:abc");
}

/// Rounding is stated, not inferred: a rate is a whole percent and entropy is
/// two decimals, at the boundaries as well as the middle.
#[test]
fn rate_and_entropy_labels_round_predictably() {
    assert_eq!(percent_label(0.0), "0%");
    assert_eq!(percent_label(1.0), "100%");
    assert_eq!(percent_label(0.746), "75%");
    assert_eq!(percent_label(0.744), "74%");
    assert_eq!(support_label(0, 0), "0 (0 confirmed · 0 rejected)");
    assert_eq!(number_label(1.0), "1");
    assert_eq!(number_label(2.5), "2.5");
}
