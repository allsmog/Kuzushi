//! Evaluator tests. The first one drives the same table
//! `experiments/review-yield/tests/test_parity_fixtures.py` drives, so a
//! routing change in either language fails on both sides.

use serde_json::{json, Map, Value};

use super::parity::{parity_fixture_path, parity_json};
use crate::review_yield::application::score_review_yield;
use crate::review_yield::domain::{
    format_threshold, FeatureLookup, FeatureValue, PathBranch, ReviewYieldEligibility,
    ReviewYieldPathStep, ValidatedReviewYieldModel, FEATURE_FIELD_NAMES, MAX_MODEL_DEPTH,
};
use crate::review_yield::persistence::{load_model_artifact, model_digest, parse_model_artifact};

/// A feature vector in the fixture's own shape: absent means "not in this
/// schema", `null` means "in the schema but not present on this finding".
struct FixtureFeatures(Map<String, Value>);

impl FeatureLookup for FixtureFeatures {
    fn feature(&self, name: &str) -> Option<FeatureValue> {
        Some(match self.0.get(name)? {
            Value::Null => FeatureValue::Missing,
            Value::Bool(flag) => FeatureValue::Boolean(*flag),
            Value::Number(number) => FeatureValue::Number(number.as_f64().unwrap_or_default()),
            other => FeatureValue::Category(other.as_str().unwrap_or_default().to_string()),
        })
    }
}

fn features(pairs: Value) -> FixtureFeatures {
    FixtureFeatures(pairs.as_object().expect("feature map").clone())
}

fn model(name: &str) -> ValidatedReviewYieldModel {
    load_model_artifact(&parity_fixture_path(name)).expect("parity model loads")
}

/// The six fields the Python evaluator returns, for a direct table comparison.
fn comparable(signal: &crate::review_yield::domain::ReviewYieldSignal) -> Value {
    json!({
        "leafId": signal.leaf_id,
        "smoothedPositiveRate": signal.smoothed_positive_rate,
        "positiveCount": signal.positive_count,
        "negativeCount": signal.negative_count,
        "path": signal.rendered_path(),
        "eligibility": serde_json::to_value(&signal.eligibility).unwrap(),
    })
}

#[test]
fn parity_fixture_scores_match_expected_tables() {
    let cases = parity_json("expected-scores.json");
    let cases = cases["cases"].as_array().expect("fixture cases");
    assert!(cases.len() >= 10, "the parity table must stay populated");

    for case in cases {
        let model = model(case["model"].as_str().unwrap());
        let signal = score_review_yield(&model, &features(case["features"].clone()));

        assert_eq!(
            comparable(&signal),
            case["expected"],
            "case {}",
            case["name"]
        );
    }
}

#[test]
fn every_documented_outcome_is_covered_by_the_parity_table() {
    let cases = parity_json("expected-scores.json");
    let mut kinds: Vec<String> = cases["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| case["expected"]["eligibility"]["kind"].as_str().unwrap().to_string())
        .collect();
    kinds.sort();
    kinds.dedup();

    assert_eq!(
        kinds,
        vec![
            "eligible",
            "insufficientLeafSupport",
            "missingRequiredFeature",
            "unknownCategory",
        ]
    );
}

#[test]
fn repeated_scoring_is_deterministic() {
    let model = model("model-mixed-depth3.json");
    let vector = features(json!({"staticProofState": "code_cited", "evidenceCount": 2}));

    let first = score_review_yield(&model, &vector);
    for _ in 0..100 {
        assert_eq!(score_review_yield(&model, &vector), first);
    }
}

#[test]
fn numeric_node_boundary_value_goes_left() {
    let model = model("model-numeric-small.json");

    let signal = score_review_yield(&model, &features(json!({"evidenceCount": 2.5})));

    assert_eq!(signal.rendered_path(), vec!["0:evidenceCount<=2.5:left"]);
    assert_eq!(signal.leaf_id, Some(1));
}

#[test]
fn missing_feature_with_ineligible_direction_yields_missing_required_feature() {
    let model = model("model-numeric-small.json");

    let signal = score_review_yield(&model, &features(json!({"evidenceCount": null})));

    assert_eq!(
        signal.eligibility,
        ReviewYieldEligibility::MissingRequiredFeature {
            feature: "evidenceCount".to_string()
        }
    );
    assert!(signal.decision_path.is_empty());
    assert_eq!(signal.smoothed_positive_rate, None);
}

#[test]
fn missing_feature_with_left_direction_routes_left() {
    let model = model("model-mixed-depth3.json");

    let signal = score_review_yield(
        &model,
        &features(json!({"staticProofState": "code_cited", "evidenceCount": null})),
    );

    assert_eq!(signal.eligibility, ReviewYieldEligibility::Eligible);
    assert_eq!(
        signal.rendered_path(),
        vec!["0:staticProofState==code_cited", "1:evidenceCount:missing-left"]
    );
}

#[test]
fn unknown_category_on_path_yields_unknown_category() {
    let model = model("model-mixed-depth3.json");

    let signal = score_review_yield(&model, &features(json!({"staticProofState": "unheard_of"})));

    assert_eq!(
        signal.eligibility,
        ReviewYieldEligibility::UnknownCategory {
            feature: "staticProofState".to_string(),
            value: "unheard_of".to_string(),
        }
    );
}

#[test]
fn unknown_feature_name_yields_missing_required_feature() {
    let model = model("model-numeric-small.json");

    let signal = score_review_yield(&model, &features(json!({})));

    assert_eq!(
        signal.eligibility,
        ReviewYieldEligibility::MissingRequiredFeature {
            feature: "evidenceCount".to_string()
        }
    );
}

#[test]
fn wrong_value_shape_for_the_node_fails_closed() {
    let model = model("model-numeric-small.json");

    let signal = score_review_yield(&model, &features(json!({"evidenceCount": "many"})));

    assert_eq!(
        signal.eligibility,
        ReviewYieldEligibility::MissingRequiredFeature {
            feature: "evidenceCount".to_string()
        }
    );
}

#[test]
fn boolean_on_a_numeric_node_evaluates_as_one_or_zero() {
    let model = model("model-numeric-small.json");

    let truthy = score_review_yield(&model, &features(json!({"evidenceCount": true})));
    let falsy = score_review_yield(&model, &features(json!({"evidenceCount": false})));

    assert_eq!(truthy.leaf_id, Some(1));
    assert_eq!(falsy.leaf_id, Some(1));
    assert_eq!(truthy.rendered_path(), vec!["0:evidenceCount<=2.5:left"]);
}

#[test]
fn leaf_below_minimum_support_yields_insufficient_leaf_support() {
    let model = model("model-mixed-depth3.json");

    let signal = score_review_yield(
        &model,
        &features(json!({"staticProofState": "signal_only", "maxEvidenceConfidence": 120})),
    );

    assert_eq!(
        signal.eligibility,
        ReviewYieldEligibility::InsufficientLeafSupport { support: 12 }
    );
    assert_eq!(signal.leaf_id, Some(5));
    assert!(signal.smoothed_positive_rate.is_some(), "thin evidence is still shown");
    assert!(!signal.is_eligible());
}

/// A model whose three categorical splits all miss the finding's vocabulary.
fn triple_categorical_model() -> ValidatedReviewYieldModel {
    let mut document = parity_json("model-numeric-small.json");
    document["nodes"] = json!([
        {"nodeType": "categorical", "id": 0, "feature": "staticProofState",
         "branches": {"code_cited": 1}, "missingDirection": "ineligible"},
        {"nodeType": "categorical", "id": 1, "feature": "vulnSource",
         "branches": {"sast": 2}, "missingDirection": "ineligible"},
        {"nodeType": "categorical", "id": 2, "feature": "toolFamily",
         "branches": {"semgrep": 3}, "missingDirection": "ineligible"},
        {"nodeType": "leaf", "id": 3, "positiveCount": 40, "negativeCount": 40,
         "smoothedPositiveRate": 0.5, "entropyBits": 1.0, "credibleInterval95": [0.4, 0.6]}
    ]);
    document["modelId"] = json!(model_digest(&document).unwrap());
    parse_model_artifact(&serde_json::to_vec(&document).unwrap()).expect("constructed model loads")
}

#[test]
fn too_many_unknown_categories_yields_out_of_distribution() {
    let model = triple_categorical_model();

    let signal = score_review_yield(
        &model,
        &features(json!({
            "staticProofState": "novel_a", "vulnSource": "novel_b", "toolFamily": "novel_c"
        })),
    );

    assert_eq!(
        signal.eligibility,
        ReviewYieldEligibility::OutOfDistribution {
            reason: "3 categorical values outside training vocabulary".to_string()
        }
    );
    assert!(signal.decision_path.is_empty());
}

#[test]
fn unknown_categories_within_the_allowance_still_walk_the_tree() {
    let model = triple_categorical_model();

    let signal = score_review_yield(
        &model,
        &features(json!({"staticProofState": "novel_a", "vulnSource": "novel_b"})),
    );

    assert_eq!(
        signal.eligibility,
        ReviewYieldEligibility::UnknownCategory {
            feature: "staticProofState".to_string(),
            value: "novel_a".to_string(),
        }
    );
}

#[test]
fn every_eligibility_variant_is_producible_or_reserved() {
    let variants = [
        ReviewYieldEligibility::Eligible,
        ReviewYieldEligibility::Disabled,
        ReviewYieldEligibility::NoModelConfigured,
        ReviewYieldEligibility::InvalidModelHash,
        ReviewYieldEligibility::UnsupportedModelSchema,
        ReviewYieldEligibility::FeatureSchemaMismatch,
        ReviewYieldEligibility::MissingRequiredFeature {
            feature: "evidenceCount".into(),
        },
        ReviewYieldEligibility::UnknownCategory {
            feature: "toolFamily".into(),
            value: "novel".into(),
        },
        ReviewYieldEligibility::InsufficientLeafSupport { support: 3 },
        ReviewYieldEligibility::OutOfDistribution {
            reason: "reason".into(),
        },
    ];

    for variant in &variants {
        let encoded = serde_json::to_value(variant).unwrap();
        assert_eq!(encoded["kind"], variant.kind(), "{variant:?}");
        assert!(!variant.kind().is_empty());
    }
}

#[test]
fn eligibility_detail_is_empty_only_when_the_kind_says_everything() {
    assert_eq!(ReviewYieldEligibility::Eligible.detail(), "");
    assert_eq!(
        ReviewYieldEligibility::InsufficientLeafSupport { support: 4 }.detail(),
        "support 4"
    );
}

#[test]
fn thresholds_render_the_way_the_canonical_form_writes_them() {
    assert_eq!(format_threshold(200.0), "200.0");
    assert_eq!(format_threshold(2.5), "2.5");
    assert_eq!(format_threshold(0.0), "0.0");
}

#[test]
fn path_steps_render_every_branch_shape() {
    let step = |taken| ReviewYieldPathStep {
        node_id: 3,
        feature: "evidenceCount".to_string(),
        taken,
    };

    assert_eq!(
        step(PathBranch::Left { threshold: 1.5 }).render(),
        "3:evidenceCount<=1.5:left"
    );
    assert_eq!(
        step(PathBranch::Right { threshold: 1.5 }).render(),
        "3:evidenceCount<=1.5:right"
    );
    assert_eq!(
        step(PathBranch::Branch {
            value: "sast".into()
        })
        .render(),
        "3:evidenceCount==sast"
    );
    assert_eq!(
        step(PathBranch::Missing {
            direction: "right".into()
        })
        .render(),
        "3:evidenceCount:missing-right"
    );
}

#[test]
fn every_schema_feature_name_resolves_through_the_lookup() {
    let features = crate::review_yield::domain::ReviewYieldFeaturesV1 {
        severity_rank: 1,
        static_proof_state: "code_cited".into(),
        vuln_source: "sast".into(),
        tool_family: "semgrep".into(),
        rule_family: "injection".into(),
        path_bucket: "src".into(),
        language_family: "rust".into(),
        identity_match_tier: "stable_fp".into(),
        grounding_status: "grounded".into(),
        is_attack_chain: false,
        evidence_count: 4,
        distinct_evidence_kinds: 2,
        max_evidence_confidence: Some(80),
        mean_evidence_confidence_millis: None,
        has_source_evidence: true,
        has_sink_evidence: true,
        has_sanitizer_evidence: false,
        has_call_path_evidence: false,
        source_sink_linked: true,
        sanitizer_checked: false,
        has_exploit_scenario: true,
        precondition_count: 1,
        source_count: 2,
        distinct_tool_count: 1,
        corroboration_count: 0,
        observation_count: 3,
        run_count: 2,
        reopened_count: 0,
        has_remediation: false,
    };

    for name in FEATURE_FIELD_NAMES {
        assert!(features.feature(name).is_some(), "{name} is not routable");
    }
    assert_eq!(features.feature("notAFeature"), None);
    assert_eq!(
        features.feature("meanEvidenceConfidenceMillis"),
        Some(FeatureValue::Missing),
        "an absent optional count stays absent instead of becoming zero"
    );
}

/// Deterministic generator: no new dev-dependency, and a failure is
/// reproducible from the seed printed in the assertion.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 33
    }
}

fn random_tree(rng: &mut Lcg) -> Vec<Value> {
    let mut nodes: Vec<Value> = vec![Value::Null];
    let mut frontier = vec![(0usize, 0usize)];
    let mut cursor = 0;
    while cursor < frontier.len() {
        let (index, depth) = frontier[cursor];
        cursor += 1;
        if depth < MAX_MODEL_DEPTH && nodes.len() + 2 <= 127 && !rng.next().is_multiple_of(3) {
            let left = nodes.len();
            nodes.push(Value::Null);
            nodes.push(Value::Null);
            frontier.push((left, depth + 1));
            frontier.push((left + 1, depth + 1));
            nodes[index] = generated_split(index, left, rng);
            continue;
        }
        nodes[index] = generated_leaf(index);
    }
    nodes
}

fn generated_split(id: usize, left: usize, rng: &mut Lcg) -> Value {
    let names = ["evidenceCount", "runCount", "sourceCount", "notAFeature"];
    let directions = ["left", "right", "ineligible"];
    json!({
        "nodeType": "numeric", "id": id,
        "feature": names[(rng.next() % 4) as usize],
        "threshold": (rng.next() % 9) as f64 + 0.5,
        "left": left, "right": left + 1,
        "missingDirection": directions[(rng.next() % 3) as usize]
    })
}

fn generated_leaf(id: usize) -> Value {
    json!({
        "nodeType": "leaf", "id": id, "positiveCount": 30, "negativeCount": 30,
        "smoothedPositiveRate": 0.5, "entropyBits": 1.0, "credibleInterval95": [0.4, 0.6]
    })
}

fn generated_features(rng: &mut Lcg) -> FixtureFeatures {
    let value = |rng: &mut Lcg| match rng.next() % 3 {
        0 => Value::Null,
        1 => json!((rng.next() % 12) as f64),
        _ => json!("unstructured"),
    };
    features(json!({
        "evidenceCount": value(rng),
        "runCount": value(rng),
        "sourceCount": value(rng),
    }))
}

#[test]
fn bounded_walk_terminates_within_depth_guard_for_generated_models() {
    let mut rng = Lcg(0x5eed_1234);
    for iteration in 0..200u32 {
        let mut document = parity_json("model-numeric-small.json");
        document["nodes"] = Value::Array(random_tree(&mut rng));
        document["modelId"] = json!(model_digest(&document).unwrap());
        let model = parse_model_artifact(&serde_json::to_vec(&document).unwrap())
            .unwrap_or_else(|error| panic!("generated model {iteration} must load: {error}"));

        let signal = score_review_yield(&model, &generated_features(&mut rng));

        assert!(
            signal.decision_path.len() <= MAX_MODEL_DEPTH,
            "iteration {iteration} walked {} steps",
            signal.decision_path.len()
        );
        assert_ne!(
            signal.eligibility,
            ReviewYieldEligibility::OutOfDistribution {
                reason: "depth guard exceeded".to_string()
            },
            "iteration {iteration} hit the guard on a model inside the bound"
        );
    }
}

#[test]
fn signal_serializes_with_camel_case_keys_for_json_output() {
    let model = model("model-numeric-small.json");

    let signal = score_review_yield(&model, &features(json!({"evidenceCount": 9})));
    let encoded = serde_json::to_value(&signal).unwrap();

    assert_eq!(encoded["eligibility"]["kind"], "eligible");
    assert_eq!(encoded["smoothedPositiveRate"], 0.828947);
    assert_eq!(encoded["decisionPath"][0]["nodeId"], 0);
    assert_eq!(encoded["featureSchemaId"], "kuzushi-review-yield-features-v1");
}
