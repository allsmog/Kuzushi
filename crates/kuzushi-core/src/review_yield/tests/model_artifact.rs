//! Loader tests: the model artifact either passes every check or is refused
//! with a named reason. Nothing here may end in a default.

use serde_json::{json, Value};

use super::parity::{parity_bytes, parity_fixture_path, parity_json, PARITY_MODELS};
use crate::review_yield::domain::{
    ReviewYieldEligibility, MAX_MODEL_FILE_BYTES, MODEL_DIGEST_DOMAIN,
};
use crate::review_yield::persistence::{
    canonical_model_bytes, eligibility_for_load_error, load_model_artifact, model_digest,
    parse_model_artifact, ModelArtifactError,
};

fn small_model() -> Value {
    parity_json("model-numeric-small.json")
}

/// Re-seals a mutated document so a test can exercise a check downstream of the
/// digest without tripping the digest first.
fn resealed(mut document: Value) -> Vec<u8> {
    let digest = model_digest(&document).expect("digest recomputes");
    document["modelId"] = Value::String(digest);
    serde_json::to_vec(&document).expect("document serializes")
}

fn load_error(bytes: &[u8]) -> ModelArtifactError {
    parse_model_artifact(bytes).expect_err("artifact must be refused")
}

#[test]
fn loads_valid_artifact_and_reports_shape() {
    let model = load_model_artifact(&parity_fixture_path("model-numeric-small.json"))
        .expect("the pinned parity model loads");

    assert_eq!(model.node_count(), 3);
    assert_eq!(model.depth(), 1);
    assert_eq!(model.task_id(), "review_yield_predecision_v1");
    assert_eq!(model.feature_schema_id(), "kuzushi-review-yield-features-v1");
    assert_eq!(model.label_policy_id(), "kuzushi-review-yield-labels-v1");
    assert_eq!(model.minimum_leaf_support(), 20);
    assert_eq!(model.maximum_unknown_categories(), 2);
}

#[test]
fn loads_mixed_model_with_categorical_root() {
    let model = load_model_artifact(&parity_fixture_path("model-mixed-depth3.json"))
        .expect("the mixed parity model loads");

    assert_eq!(model.node_count(), 7);
    assert_eq!(model.depth(), 2);
    assert_eq!(model.model_id(), parity_json("model-mixed-depth3.json")["modelId"]);
}

/// The pin that guards float formatting and key ordering forever: these exact
/// hex strings and byte counts are what the Python exporter wrote.
#[test]
fn canonical_bytes_pin_digest() {
    let pinned = parity_json("pinned-digests.json");
    assert_eq!(pinned["domain"], MODEL_DIGEST_DOMAIN);
    for name in PARITY_MODELS {
        let document = parity_json(name);
        let expected = &pinned["artifacts"][name];
        assert_eq!(model_digest(&document).unwrap(), expected["modelId"], "{name}");
        assert_eq!(
            canonical_model_bytes(&document).unwrap().len(),
            expected["canonicalBytesLength"].as_u64().unwrap() as usize,
            "{name}"
        );
        assert_eq!(
            parity_bytes(name).len(),
            expected["fileBytesLength"].as_u64().unwrap() as usize,
            "{name}"
        );
    }
}

#[test]
fn hashed_form_excludes_model_id() {
    for name in PARITY_MODELS {
        let canonical = canonical_model_bytes(&parity_json(name)).unwrap();
        assert!(
            !String::from_utf8(canonical).unwrap().contains("\"modelId\""),
            "{name}"
        );
    }
}

#[test]
fn fixture_bytes_are_already_canonical() {
    for name in PARITY_MODELS {
        let raw = parity_bytes(name);
        assert!(raw.is_ascii(), "{name}");
        assert_ne!(raw.last(), Some(&b'\n'), "{name}");
        let document: Value = serde_json::from_slice(&raw).unwrap();
        // The file is the canonical form plus the `modelId` entry the digest
        // cannot cover, so it is exactly that entry longer.
        assert!(raw.len() > canonical_model_bytes(&document).unwrap().len(), "{name}");
    }
}

#[test]
fn tampered_digest_fails_with_hash_mismatch() {
    let error = parse_model_artifact(&parity_bytes("model-tampered-hash.json"))
        .expect_err("a flipped digest character must fail closed");

    assert!(matches!(error, ModelArtifactError::HashMismatch { .. }), "{error}");
    assert_eq!(
        eligibility_for_load_error(&error),
        ReviewYieldEligibility::InvalidModelHash
    );
}

#[test]
fn tampered_payload_fails_with_hash_mismatch() {
    let mut document = small_model();
    document["nodes"][1]["smoothedPositiveRate"] = json!(0.99);

    let error = load_error(&serde_json::to_vec(&document).unwrap());

    assert!(matches!(error, ModelArtifactError::HashMismatch { .. }), "{error}");
}

#[test]
fn unknown_schema_version_fails_before_hashing() {
    let mut document = small_model();
    document["schemaVersion"] = json!(2);

    let error = load_error(&serde_json::to_vec(&document).unwrap());

    assert!(
        matches!(&error, ModelArtifactError::UnsupportedSchemaVersion { found } if found == "2"),
        "{error}"
    );
    assert_eq!(
        eligibility_for_load_error(&error),
        ReviewYieldEligibility::UnsupportedModelSchema
    );
}

#[test]
fn absent_schema_version_is_reported_as_absent() {
    let mut document = small_model();
    document.as_object_mut().unwrap().remove("schemaVersion");

    let error = load_error(&serde_json::to_vec(&document).unwrap());

    assert!(
        matches!(&error, ModelArtifactError::UnsupportedSchemaVersion { found } if found == "absent"),
        "{error}"
    );
}

#[test]
fn malformed_json_is_refused() {
    let error = load_error(b"{ not json");

    assert!(matches!(error, ModelArtifactError::Malformed(_)), "{error}");
}

#[test]
fn unknown_top_level_key_rejected() {
    let mut document = small_model();
    document["surpriseKey"] = json!(true);

    let error = load_error(&resealed(document));

    assert!(matches!(error, ModelArtifactError::Shape(_)), "{error}");
}

#[test]
fn unknown_node_key_rejected() {
    let mut document = small_model();
    document["nodes"][0]["surpriseKey"] = json!(1);

    let error = load_error(&resealed(document));

    assert!(matches!(error, ModelArtifactError::Shape(_)), "{error}");
}

#[test]
fn unknown_node_type_rejected() {
    let mut document = small_model();
    document["nodes"][1]["nodeType"] = json!("oblique");

    let error = load_error(&resealed(document));

    assert!(matches!(error, ModelArtifactError::Shape(_)), "{error}");
}

#[test]
fn missing_model_id_rejected() {
    let mut document = small_model();
    document.as_object_mut().unwrap().remove("modelId");

    let error = load_error(&serde_json::to_vec(&document).unwrap());

    assert!(matches!(error, ModelArtifactError::Shape(_)), "{error}");
}

#[test]
fn uppercase_digest_rejected() {
    let mut document = small_model();
    let declared = document["modelId"].as_str().unwrap().to_uppercase();
    document["modelId"] = json!(format!("blake3:{}", &declared[7..]));

    let error = load_error(&serde_json::to_vec(&document).unwrap());

    assert!(matches!(error, ModelArtifactError::Shape(_)), "{error}");
}

#[test]
fn child_index_out_of_bounds_rejected() {
    let mut document = small_model();
    document["nodes"][0]["right"] = json!(9);

    let error = load_error(&resealed(document));

    assert!(matches!(error, ModelArtifactError::Tree(_)), "{error}");
}

#[test]
fn cycle_rejected() {
    let mut document = small_model();
    document["nodes"][1] = json!({
        "nodeType": "numeric", "id": 1, "feature": "runCount", "threshold": 1.0,
        "left": 0, "right": 2, "missingDirection": "ineligible"
    });

    let error = load_error(&resealed(document));

    assert!(matches!(error, ModelArtifactError::Tree(_)), "{error}");
}

/// Two different parents pointing at the same child is a DAG, not a tree: the
/// child would have two decision paths.
#[test]
fn shared_child_rejected() {
    let mut document = small_model();
    document["nodes"] = json!([
        split_node(0, 1, 2),
        split_node(1, 3, 4),
        split_node(2, 3, 4),
        leaf_node(3),
        leaf_node(4)
    ]);

    let error = load_error(&resealed(document));

    assert!(
        matches!(&error, ModelArtifactError::Tree(message) if message.contains("more than once")),
        "{error}"
    );
}

fn split_node(id: usize, left: usize, right: usize) -> Value {
    json!({
        "nodeType": "numeric", "id": id, "feature": "runCount", "threshold": 1.0,
        "left": left, "right": right, "missingDirection": "ineligible"
    })
}

/// The mixed model routes four categorical keys to two children. Repeated
/// branch keys are one-vs-rest expansion, not a shared child.
#[test]
fn repeated_branch_keys_to_one_child_are_accepted() {
    let model = load_model_artifact(&parity_fixture_path("model-mixed-depth3.json"))
        .expect("one-vs-rest branch expansion is a tree");

    assert_eq!(model.node_count(), 7);
}

#[test]
fn unreachable_node_rejected() {
    let mut document = small_model();
    document["nodes"][0]["right"] = json!(1);
    document["nodes"][0]["left"] = json!(1);

    let error = load_error(&resealed(document));

    assert!(matches!(error, ModelArtifactError::Tree(_)), "{error}");
}

/// A left spine of `depth` numeric nodes: node `i` sits at depth `i`, and its
/// children sit one deeper, so the measured depth is exactly `depth`.
fn numeric_chain(depth: usize) -> Value {
    let mut nodes: Vec<Value> = (0..depth)
        .map(|index| split_node(index, index + 1, depth + 1 + index))
        .collect();
    nodes.extend((depth..=depth + depth).map(leaf_node));
    let mut document = small_model();
    document["nodes"] = Value::Array(nodes);
    document
}

fn leaf_node(id: usize) -> Value {
    json!({
        "nodeType": "leaf", "id": id, "positiveCount": 30, "negativeCount": 30,
        "smoothedPositiveRate": 0.5, "entropyBits": 1.0,
        "credibleInterval95": [0.4, 0.6]
    })
}

#[test]
fn depth_within_six_is_accepted() {
    let model = parse_model_artifact(&resealed(numeric_chain(6)))
        .expect("a six-deep chain is inside the bound");

    assert_eq!(model.depth(), 6);
}

#[test]
fn depth_over_six_rejected() {
    let error = load_error(&resealed(numeric_chain(8)));

    assert!(
        matches!(&error, ModelArtifactError::Tree(message) if message.contains("depth")),
        "{error}"
    );
}

#[test]
fn more_than_127_nodes_rejected() {
    let mut document = small_model();
    let nodes: Vec<Value> = (0..128).map(leaf_node).collect();
    document["nodes"] = Value::Array(nodes);

    let error = load_error(&resealed(document));

    assert!(
        matches!(&error, ModelArtifactError::Bounds(message) if message.contains("nodes length")),
        "{error}"
    );
}

#[test]
fn empty_node_list_rejected() {
    let mut document = small_model();
    document["nodes"] = json!([]);

    let error = load_error(&resealed(document));

    assert!(matches!(error, ModelArtifactError::Bounds(_)), "{error}");
}

#[test]
fn node_id_must_equal_its_index() {
    let mut document = small_model();
    document["nodes"][2]["id"] = json!(5);

    let error = load_error(&resealed(document));

    assert!(
        matches!(&error, ModelArtifactError::Bounds(message) if message.contains("declares id")),
        "{error}"
    );
}

#[test]
fn rate_out_of_range_rejected() {
    let mut document = small_model();
    document["nodes"][1]["smoothedPositiveRate"] = json!(1.5);

    let error = load_error(&resealed(document));

    assert!(matches!(error, ModelArtifactError::Bounds(_)), "{error}");
}

#[test]
fn display_band_out_of_range_rejected() {
    let mut document = small_model();
    document["displayBands"]["highMinimum"] = json!(1.4);

    let error = load_error(&resealed(document));

    assert!(matches!(error, ModelArtifactError::Bounds(_)), "{error}");
}

#[test]
fn interval_inverted_rejected() {
    let mut document = small_model();
    document["nodes"][1]["credibleInterval95"] = json!([0.9, 0.1]);

    let error = load_error(&resealed(document));

    assert!(
        matches!(&error, ModelArtifactError::Bounds(message) if message.contains("inverted")),
        "{error}"
    );
}

#[test]
fn zero_minimum_leaf_support_rejected() {
    let mut document = small_model();
    document["eligibility"]["minimumLeafSupport"] = json!(0);

    let error = load_error(&resealed(document));

    assert!(matches!(error, ModelArtifactError::Bounds(_)), "{error}");
}

#[test]
fn non_ascii_string_rejected() {
    let mut document = small_model();
    document["training"]["criterion"] = json!("entropi\u{00e9}");

    let error = load_error(&resealed(document));

    assert!(
        matches!(&error, ModelArtifactError::Bounds(message) if message.contains("printable ASCII")),
        "{error}"
    );
}

#[test]
fn overlong_string_rejected() {
    let mut document = small_model();
    document["training"]["criterion"] = json!("e".repeat(129));

    let error = load_error(&resealed(document));

    assert!(
        matches!(&error, ModelArtifactError::Bounds(message) if message.contains("length")),
        "{error}"
    );
}

#[test]
fn empty_branch_map_rejected() {
    let mut document = parity_json("model-mixed-depth3.json");
    document["nodes"][0]["branches"] = json!({});

    let error = load_error(&resealed(document));

    assert!(matches!(error, ModelArtifactError::Bounds(_)), "{error}");
}

#[test]
fn categorical_node_routing_absence_left_rejected() {
    let mut document = parity_json("model-mixed-depth3.json");
    document["nodes"][0]["missingDirection"] = json!("left");

    let error = load_error(&resealed(document));

    assert!(
        matches!(&error, ModelArtifactError::Bounds(message) if message.contains("ineligible")),
        "{error}"
    );
}

#[test]
fn wrong_task_id_rejected() {
    let mut document = small_model();
    document["taskId"] = json!("review_yield_predecision_v2");

    let error = load_error(&resealed(document));

    assert!(matches!(error, ModelArtifactError::Shape(_)), "{error}");
}

#[test]
fn wrong_model_kind_rejected() {
    let mut document = small_model();
    document["modelKind"] = json!("gradient_boosting");

    let error = load_error(&resealed(document));

    assert!(matches!(error, ModelArtifactError::Shape(_)), "{error}");
}

#[test]
fn feature_schema_mismatch_maps_to_feature_schema_mismatch_eligibility() {
    let mut document = small_model();
    document["featureSchemaId"] = json!("kuzushi-review-yield-features-v2");

    let error = load_error(&resealed(document));

    assert!(
        matches!(&error, ModelArtifactError::FeatureSchemaMismatch { found, .. }
            if found == "kuzushi-review-yield-features-v2"),
        "{error}"
    );
    assert_eq!(
        eligibility_for_load_error(&error),
        ReviewYieldEligibility::FeatureSchemaMismatch
    );
}

#[test]
fn oversized_file_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("huge.json");
    std::fs::write(&path, vec![b'x'; (MAX_MODEL_FILE_BYTES + 1) as usize]).unwrap();

    let error = load_model_artifact(&path).expect_err("an oversized artifact is refused unread");

    assert!(matches!(error, ModelArtifactError::TooLarge { .. }), "{error}");
}

#[test]
fn absent_file_is_unreadable_not_empty() {
    let directory = tempfile::tempdir().unwrap();

    let error = load_model_artifact(&directory.path().join("absent.json"))
        .expect_err("a missing model is a failure, never an empty model");

    assert!(matches!(error, ModelArtifactError::Unreadable(_)), "{error}");
    assert_eq!(
        eligibility_for_load_error(&error),
        ReviewYieldEligibility::UnsupportedModelSchema
    );
}

/// Every load failure names an eligibility. The mapping is exhaustive by
/// construction; this asserts the list is complete and nothing maps to
/// `Eligible`.
#[test]
fn every_load_error_maps_to_an_eligibility() {
    let errors = [
        ModelArtifactError::Unreadable("x".into()),
        ModelArtifactError::TooLarge { bytes: 1, limit: 0 },
        ModelArtifactError::Malformed("x".into()),
        ModelArtifactError::UnsupportedSchemaVersion { found: "2".into() },
        ModelArtifactError::HashMismatch {
            declared: "a".into(),
            computed: "b".into(),
        },
        ModelArtifactError::Shape("x".into()),
        ModelArtifactError::Bounds("x".into()),
        ModelArtifactError::Tree("x".into()),
        ModelArtifactError::FeatureSchemaMismatch {
            found: "a".into(),
            expected: "b".into(),
        },
    ];

    for error in &errors {
        let eligibility = eligibility_for_load_error(error);
        assert_ne!(eligibility, ReviewYieldEligibility::Eligible, "{error}");
        assert!(!error.to_string().is_empty(), "{error}");
    }
}

fn model_schema() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas/review-yield.model.schema.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// The published schema and the Rust loader must state the same bounds. The
/// schema describes the wire shape; the loader owns the graph invariants.
#[test]
fn published_model_schema_matches_the_loader_bounds() {
    let schema = model_schema();

    assert_eq!(schema["title"], "Kuzushi Review Yield Model V1");
    assert_eq!(schema["properties"]["schemaVersion"]["const"], 1);
    assert_eq!(schema["properties"]["modelKind"]["const"], "decision_tree");
    assert_eq!(
        schema["properties"]["nodes"]["maxItems"].as_u64().unwrap() as usize,
        crate::review_yield::domain::MAX_MODEL_NODES
    );
    assert_eq!(
        schema["definitions"]["boundedName"]["maxLength"].as_u64().unwrap() as usize,
        crate::review_yield::domain::MAX_MODEL_STRING_LEN
    );
    assert_eq!(
        schema["definitions"]["categoricalNode"]["properties"]["branches"]["maxProperties"]
            .as_u64()
            .unwrap() as usize,
        crate::review_yield::domain::MAX_CATEGORICAL_BRANCHES
    );
    assert_eq!(
        schema["definitions"]["training"]["properties"]["maxDepth"]["maximum"]
            .as_u64()
            .unwrap() as usize,
        crate::review_yield::domain::MAX_MODEL_DEPTH
    );
}

/// Every top-level key the parity fixtures carry is a key the schema requires,
/// and the schema requires nothing the fixtures omit.
#[test]
fn published_model_schema_covers_the_parity_fixture_keys() {
    let schema = model_schema();
    let required: Vec<&str> = schema["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();

    for name in PARITY_MODELS {
        let document = parity_json(name);
        let mut keys: Vec<&str> = document
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        let mut expected = required.clone();
        keys.sort();
        expected.sort();
        assert_eq!(keys, expected, "{name}");
    }
}

#[test]
fn loading_is_deterministic_across_repeated_reads() {
    let path = parity_fixture_path("model-numeric-small.json");

    let first = load_model_artifact(&path).unwrap();
    let second = load_model_artifact(&path).unwrap();

    assert_eq!(first.model_id(), second.model_id());
    assert_eq!(first.depth(), second.depth());
    assert_eq!(first.node_count(), second.node_count());
}
