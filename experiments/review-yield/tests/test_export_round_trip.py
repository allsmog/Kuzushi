"""Model artifact canonicalization, digest, and honesty checks (design §18)."""

import json
import tempfile
import unittest
from pathlib import Path

from support import has_module, tiny_rows

from kuzushi_review_yield.export_model import (
    MODEL_DIGEST_DOMAIN,
    ExportError,
    MeasuredEvaluation,
    TrainingProvenance,
    artifact_bytes,
    build_artifact,
    hashed_bytes,
    model_id,
    verify_artifact,
    verify_artifact_bytes,
    write_artifact,
)
from kuzushi_review_yield.hashing import (
    CanonicalizationError,
    canonical_json_bytes,
    hash_parts,
    quantize_floats,
)
from kuzushi_review_yield.id3 import build_category_map, default_feature_schema, fit_id3

SCHEMA = default_feature_schema()

MEASURED = MeasuredEvaluation(
    precision_at_20=0.625,
    recall_at_20=0.25,
    pr_auc=0.652023,
    brier=0.205708,
    measured_on_dataset_digest="blake3:" + "ab" * 32,
)

TRAINING = TrainingProvenance(
    dataset_digest="blake3:" + "ab" * 32,
    training_cutoff_seq=9000,
    random_seed=6601,
    max_depth=2,
    min_samples_leaf=1,
)


def tiny_artifact(**overrides):
    rows = tiny_rows()
    tree = fit_id3(
        rows, SCHEMA, max_depth=2, min_samples_leaf=1, min_gain=0.0, rare_category_min_count=1
    )
    categories = build_category_map(rows, SCHEMA, 1)
    options = {"training": TRAINING, "evaluation": MEASURED}
    options.update(overrides)
    return build_artifact(tree, categories, **options)


class CanonicalFormTest(unittest.TestCase):
    def test_canonical_bytes_sorted_compact_ascii(self):
        raw = canonical_json_bytes({"b": 1, "a": {"d": 2, "c": [3, 4]}})
        self.assertEqual(raw, b'{"a":{"c":[3,4],"d":2},"b":1}')
        self.assertTrue(raw.isascii())

    def test_non_ascii_is_refused(self):
        with self.assertRaises(CanonicalizationError) as caught:
            canonical_json_bytes({"note": "café"})
        self.assertIn("ASCII-only", str(caught.exception))

    def test_float_quantization_six_places(self):
        quantized = quantize_floats({"rate": 0.07142857142857142, "counts": [1, 2]})
        self.assertEqual(quantized["rate"], 0.071429)
        self.assertEqual(quantized["counts"], [1, 2])

    def test_tiny_magnitudes_snap_to_zero_so_no_exponent_is_written(self):
        self.assertEqual(quantize_floats(3e-6), 0.0)
        self.assertEqual(canonical_json_bytes(quantize_floats({"x": 3e-6})), b'{"x":0.0}')

    def test_exponent_notation_is_refused_before_it_reaches_the_bytes(self):
        with self.assertRaises(CanonicalizationError) as caught:
            canonical_json_bytes({"x": 3e-6})
        self.assertIn("exponent notation", str(caught.exception))

    def test_integers_keep_their_integer_form(self):
        self.assertEqual(canonical_json_bytes(quantize_floats({"n": 12})), b'{"n":12}')

    def test_non_finite_floats_are_refused(self):
        with self.assertRaises(CanonicalizationError):
            quantize_floats({"x": float("inf")})


class DigestFramingTest(unittest.TestCase):
    def test_framing_matches_hash_parts_by_construction(self):
        # blake3(u64_be(10)||"kuzushi:v3"||u64_be(len(d))||d||u64_be(len(p))||p)
        from kuzushi_review_yield.blake3_pure import Blake3Hasher

        payload = b'{"a":1}'
        hasher = Blake3Hasher()
        for part in (b"kuzushi:v3", MODEL_DIGEST_DOMAIN.encode(), payload):
            hasher.update(len(part).to_bytes(8, "big"))
            hasher.update(part)
        self.assertEqual(hash_parts(MODEL_DIGEST_DOMAIN, [payload]), hasher.hexdigest())

    def test_domain_separation_changes_the_digest(self):
        self.assertNotEqual(
            hash_parts(MODEL_DIGEST_DOMAIN, [b"same"]), hash_parts("other-domain", [b"same"])
        )

    def test_length_framing_prevents_boundary_ambiguity(self):
        self.assertNotEqual(
            hash_parts("d", [b"ab", b"c"]), hash_parts("d", [b"a", b"bc"])
        )


class ArtifactTest(unittest.TestCase):
    def setUp(self):
        self.artifact = tiny_artifact()

    def test_artifact_schema_fields_match_section_18(self):
        self.assertEqual(
            sorted(self.artifact),
            [
                "displayBands",
                "eligibility",
                "evaluation",
                "featureSchemaId",
                "labelPolicyId",
                "modelId",
                "modelKind",
                "nodes",
                "schemaVersion",
                "taskId",
                "training",
            ],
        )
        self.assertEqual(self.artifact["schemaVersion"], 1)
        self.assertEqual(self.artifact["modelKind"], "decision_tree")
        self.assertEqual(self.artifact["taskId"], "review_yield_predecision_v1")

    def test_model_id_excludes_itself_from_the_hashed_form(self):
        self.assertNotIn(b"modelId", hashed_bytes(self.artifact))
        self.assertEqual(model_id(self.artifact), self.artifact["modelId"])

    def test_digest_verify_round_trip(self):
        self.assertEqual(verify_artifact_bytes(artifact_bytes(self.artifact)),
                         self.artifact["modelId"])

    def test_tampered_payload_fails_verification(self):
        tampered = json.loads(artifact_bytes(self.artifact))
        tampered["nodes"][1]["smoothedPositiveRate"] = 0.999
        with self.assertRaises(ExportError) as caught:
            verify_artifact_bytes(canonical_json_bytes(tampered))
        self.assertIn("digest mismatch", str(caught.exception))

    def test_tampered_digest_fails_verification(self):
        tampered = json.loads(artifact_bytes(self.artifact))
        tampered["modelId"] = tampered["modelId"][:-1] + "0"
        with self.assertRaises(ExportError):
            verify_artifact_bytes(canonical_json_bytes(tampered))

    def test_missing_model_id_fails_verification(self):
        tampered = {k: v for k, v in self.artifact.items() if k != "modelId"}
        with self.assertRaises(ExportError) as caught:
            verify_artifact_bytes(canonical_json_bytes(tampered))
        self.assertIn("modelId", str(caught.exception))

    def test_non_canonical_bytes_fail_verification(self):
        pretty = json.dumps(self.artifact, indent=2).encode("utf-8")
        with self.assertRaises(ExportError) as caught:
            verify_artifact_bytes(pretty)
        self.assertIn("canonical", str(caught.exception))

    def test_written_file_verifies(self):
        with tempfile.TemporaryDirectory() as directory:
            path = write_artifact(Path(directory) / "model.json", self.artifact)
            self.assertEqual(verify_artifact(path), self.artifact["modelId"])

    def test_nodes_are_pre_order_with_forward_child_references(self):
        for node in self.artifact["nodes"]:
            if node["nodeType"] == "numeric":
                self.assertGreater(node["left"], node["id"])
                self.assertGreater(node["right"], node["id"])
            if node["nodeType"] == "categorical":
                for child in node["branches"].values():
                    self.assertGreater(child, node["id"])

    def test_every_internal_node_declares_missing_ineligible(self):
        for node in self.artifact["nodes"]:
            if node["nodeType"] != "leaf":
                self.assertEqual(node["missingDirection"], "ineligible")

    def test_leaves_carry_counts_rate_entropy_and_interval(self):
        leaves = [n for n in self.artifact["nodes"] if n["nodeType"] == "leaf"]
        self.assertEqual(len(leaves), 3)
        for leaf in leaves:
            low, high = leaf["credibleInterval95"]
            self.assertLessEqual(0.0, low)
            self.assertLess(low, leaf["smoothedPositiveRate"])
            self.assertLess(leaf["smoothedPositiveRate"], high)
            self.assertLessEqual(high, 1.0)
            self.assertGreaterEqual(leaf["entropyBits"], 0.0)

    def test_reject_illustrative_metrics(self):
        illustrative = MeasuredEvaluation(0.0, 0.0, 0.0, 0.0, "blake3:" + "cd" * 32)
        with self.assertRaises(ExportError) as caught:
            tiny_artifact(evaluation=illustrative)
        self.assertIn("illustrative", str(caught.exception))

    def test_reject_metrics_with_no_dataset_digest(self):
        anonymous = MeasuredEvaluation(0.5, 0.5, 0.5, 0.2, "")
        with self.assertRaises(ExportError) as caught:
            tiny_artifact(evaluation=anonymous)
        self.assertIn("dataset digest", str(caught.exception))

    def test_export_is_byte_stable_across_rebuilds(self):
        self.assertEqual(artifact_bytes(tiny_artifact()), artifact_bytes(tiny_artifact()))

    @unittest.skipUnless(has_module("blake3"), "optional blake3 binding not installed")
    def test_pure_python_digest_matches_the_official_binding(self):
        import blake3

        payload = hashed_bytes(self.artifact)
        hasher = blake3.blake3()
        for part in (b"kuzushi:v3", MODEL_DIGEST_DOMAIN.encode(), payload):
            hasher.update(len(part).to_bytes(8, "big"))
            hasher.update(part)
        self.assertEqual(self.artifact["modelId"], f"blake3:{hasher.hexdigest()}")


if __name__ == "__main__":
    unittest.main()
