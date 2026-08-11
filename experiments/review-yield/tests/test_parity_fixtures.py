"""The Python half of the Python<->Rust model contract.

PR 4's Rust tests read these same files and must reproduce the same digests and
the same feature-to-leaf tables. If a change here passes but the Rust twin
fails, the canonical rule has drifted and one of the two is wrong.
"""

import json
import unittest

from support import PARITY, parity_json

from kuzushi_review_yield.artifact_eval import evaluate_artifact
from kuzushi_review_yield.export_model import (
    ExportError,
    hashed_bytes,
    model_id,
    verify_artifact,
    verify_artifact_bytes,
)

MODELS = ("model-numeric-small.json", "model-mixed-depth3.json")


class PinnedDigestTest(unittest.TestCase):
    def setUp(self):
        self.pinned = parity_json("pinned-digests.json")

    def test_domain_and_framing_are_pinned(self):
        self.assertEqual(self.pinned["domain"], "kuzushi-review-yield-model-v1")
        self.assertIn("kuzushi:v3", self.pinned["framing"])

    def test_canonical_bytes_pin_digest(self):
        for name in MODELS:
            with self.subTest(model=name):
                artifact = parity_json(name)
                expected = self.pinned["artifacts"][name]
                self.assertEqual(model_id(artifact), expected["modelId"])
                self.assertEqual(len(hashed_bytes(artifact)), expected["canonicalBytesLength"])
                self.assertEqual(
                    len((PARITY / name).read_bytes()), expected["fileBytesLength"]
                )

    def test_every_model_fixture_verifies(self):
        for name in MODELS:
            with self.subTest(model=name):
                self.assertEqual(verify_artifact(PARITY / name), parity_json(name)["modelId"])

    def test_tampered_fixture_fails_closed(self):
        with self.assertRaises(ExportError) as caught:
            verify_artifact(PARITY / "model-tampered-hash.json")
        self.assertIn("digest mismatch", str(caught.exception))

    def test_tampered_fixture_differs_only_in_the_digest(self):
        original = json.loads((PARITY / "model-numeric-small.json").read_bytes())
        tampered = json.loads((PARITY / "model-tampered-hash.json").read_bytes())
        differing = {key for key in original if original[key] != tampered.get(key)}
        self.assertEqual(differing, {"modelId"})

    def test_hashed_form_excludes_model_id(self):
        for name in MODELS:
            with self.subTest(model=name):
                self.assertNotIn(b'"modelId"', hashed_bytes(parity_json(name)))

    def test_fixture_bytes_are_canonical(self):
        for name in MODELS:
            with self.subTest(model=name):
                raw = (PARITY / name).read_bytes()
                self.assertTrue(raw.isascii())
                self.assertFalse(raw.endswith(b"\n"))
                verify_artifact_bytes(raw)


class ExpectedScoreTest(unittest.TestCase):
    def setUp(self):
        self.cases = parity_json("expected-scores.json")["cases"]
        self.artifacts = {name: parity_json(name) for name in MODELS}

    def test_parity_fixture_scores_match_expected_tables(self):
        for case in self.cases:
            with self.subTest(case=case["name"]):
                actual = evaluate_artifact(self.artifacts[case["model"]], case["features"])
                self.assertEqual(actual, case["expected"])

    def test_every_documented_outcome_is_covered(self):
        kinds = {case["expected"]["eligibility"]["kind"] for case in self.cases}
        self.assertEqual(
            kinds,
            {
                "eligible",
                "missingRequiredFeature",
                "unknownCategory",
                "insufficientLeafSupport",
            },
        )

    def test_threshold_boundary_goes_left(self):
        case = next(c for c in self.cases if c["name"] == "threshold boundary goes left")
        self.assertEqual(case["features"]["evidenceCount"], 2.5)
        self.assertEqual(case["expected"]["path"], ["0:evidenceCount<=2.5:left"])

    def test_missing_direction_left_is_followed(self):
        case = next(c for c in self.cases if c["name"] == "missing numeric routed left")
        self.assertIn("1:evidenceCount:missing-left", case["expected"]["path"])
        self.assertEqual(case["expected"]["eligibility"]["kind"], "eligible")

    def test_under_support_leaf_still_reports_its_stats(self):
        case = next(c for c in self.cases if c["name"] == "under-support leaf")
        self.assertEqual(case["expected"]["eligibility"], {"kind": "insufficientLeafSupport", "support": 12})
        self.assertIsNotNone(case["expected"]["smoothedPositiveRate"])

    def test_scoring_is_deterministic(self):
        case = self.cases[0]
        artifact = self.artifacts[case["model"]]
        results = {
            json.dumps(evaluate_artifact(artifact, case["features"]), sort_keys=True)
            for _ in range(50)
        }
        self.assertEqual(len(results), 1)

    def test_models_stay_within_the_loader_bounds(self):
        for name, artifact in self.artifacts.items():
            with self.subTest(model=name):
                self.assertLessEqual(len(artifact["nodes"]), 127)
                self.assertGreaterEqual(len(artifact["nodes"]), 1)

    def test_no_node_has_two_parents(self):
        # PR 4's loader rejects a node reachable from two parents. Several branch
        # keys of one categorical node may share a child — that is what one-vs-rest
        # expansion produces — so children are de-duplicated per node first.
        for name, artifact in self.artifacts.items():
            with self.subTest(model=name):
                seen: set[int] = set()
                for node in artifact["nodes"]:
                    for child in sorted(set(_children(node))):
                        self.assertNotIn(child, seen, f"node {child} has two parents")
                        seen.add(child)

    def test_every_node_except_the_root_is_reachable(self):
        for name, artifact in self.artifacts.items():
            with self.subTest(model=name):
                reachable = {0}
                for node in artifact["nodes"]:
                    reachable.update(_children(node))
                self.assertEqual(reachable, {node["id"] for node in artifact["nodes"]})


def _children(node):
    if node["nodeType"] == "numeric":
        return [node["left"], node["right"]]
    if node["nodeType"] == "categorical":
        return list(node["branches"].values())
    return []


if __name__ == "__main__":
    unittest.main()
