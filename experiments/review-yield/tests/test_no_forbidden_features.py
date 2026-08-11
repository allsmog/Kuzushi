"""Leakage tests. Design §23.2.

The Rust exporter cannot serialize a forbidden key — the whitelist struct has no
field for it. These tests prove the Python loader is the same kind of wall: a row
carrying the outcome, or an unknown key, or a `missing` cutoff quality, fails to
load rather than being silently trimmed.
"""

import tempfile
import unittest
from pathlib import Path

from support import TINY_MANIFEST, tiny_records, tiny_rows

from kuzushi_review_yield.dataset import (
    CATEGORICAL_FEATURES,
    CATEGORICAL_VOCABULARY,
    EXPORTED_CUTOFF_QUALITY,
    FEATURE_WHITELIST,
    FORBIDDEN_KEYS,
    NUMERIC_FEATURES,
    BOOLEAN_FEATURES,
    DatasetError,
    load_jsonl,
)
from kuzushi_review_yield.hashing import canonical_json_bytes

import json


def write(records):
    handle = tempfile.NamedTemporaryFile("wb", suffix=".jsonl", delete=False)
    handle.write(b"".join(canonical_json_bytes(record) + b"\n" for record in records))
    handle.close()
    return Path(handle.name)


class FeatureWhitelistTest(unittest.TestCase):
    def test_whitelist_matches_the_exporter_field_order(self):
        # The manifest is written by the same contract the Rust exporter uses.
        manifest = json.loads(TINY_MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(manifest["featureFields"], list(FEATURE_WHITELIST))
        self.assertEqual(len(FEATURE_WHITELIST), 29)

    def test_every_feature_has_exactly_one_kind(self):
        kinds = [CATEGORICAL_FEATURES, BOOLEAN_FEATURES, NUMERIC_FEATURES]
        for name in FEATURE_WHITELIST:
            with self.subTest(feature=name):
                self.assertEqual(sum(name in kind for kind in kinds), 1)

    def test_forbidden_key_fails_load(self):
        for key in ["triage", "rationale", "path", "snippet", "reviewer"]:
            with self.subTest(key=key):
                records = tiny_records()
                records[0]["features"][key] = "leaked"
                with self.assertRaises(DatasetError) as caught:
                    load_jsonl(write(records))
                self.assertIn("forbidden feature key", str(caught.exception))

    def test_forbidden_keys_are_disjoint_from_the_whitelist(self):
        self.assertEqual(FORBIDDEN_KEYS & set(FEATURE_WHITELIST), set())

    def test_unknown_feature_key_fails_load(self):
        records = tiny_records()
        records[0]["features"]["experimentalScore"] = 1
        with self.assertRaises(DatasetError) as caught:
            load_jsonl(write(records))
        self.assertIn("unknown feature key", str(caught.exception))

    def test_absent_feature_key_fails_load(self):
        records = tiny_records()
        del records[0]["features"]["hasRemediation"]
        with self.assertRaises(DatasetError) as caught:
            load_jsonl(write(records))
        self.assertIn("absent feature key", str(caught.exception))

    def test_cutoff_quality_vocabulary(self):
        self.assertEqual(
            set(row.cutoff_quality for row in tiny_rows()), set(EXPORTED_CUTOFF_QUALITY)
        )

    def test_missing_cutoff_quality_is_never_a_training_row(self):
        records = tiny_records()
        records[0]["quality"]["cutoffQuality"] = "missing"
        with self.assertRaises(DatasetError) as caught:
            load_jsonl(write(records))
        self.assertIn("never exported", str(caught.exception))

    def test_unknown_cutoff_quality_fails_load(self):
        records = tiny_records()
        records[0]["quality"]["cutoffQuality"] = "exact"
        with self.assertRaises(DatasetError):
            load_jsonl(write(records))

    def test_category_outside_the_frozen_vocabulary_fails_load(self):
        records = tiny_records()
        records[0]["features"]["staticProofState"] = "definitely_exploitable"
        with self.assertRaises(DatasetError) as caught:
            load_jsonl(write(records))
        self.assertIn("outside the frozen vocabulary", str(caught.exception))

    def test_cwe_rule_family_token_is_accepted(self):
        records = tiny_records()
        records[0]["features"]["ruleFamily"] = "cwe-89"
        self.assertEqual(load_jsonl(write(records))[0].features["ruleFamily"], "cwe-89")

    def test_identity_match_tier_uses_the_real_vocabulary(self):
        self.assertEqual(
            CATEGORICAL_VOCABULARY["identityMatchTier"],
            ("dedup_collision", "dedup_key_cross_run", "model_dedupe", "stable_fp", "unknown"),
        )

    def test_nullable_features_are_the_only_ones_that_may_be_absent(self):
        records = tiny_records()
        records[0]["features"]["maxEvidenceConfidence"] = None
        self.assertIsNone(load_jsonl(write(records))[0].features["maxEvidenceConfidence"])
        records[0]["features"]["evidenceCount"] = None
        with self.assertRaises(DatasetError) as caught:
            load_jsonl(write(records))
        self.assertIn("may not be null", str(caught.exception))

    def test_label_conflict_rows_are_never_exported(self):
        records = tiny_records()
        records[0]["labelConflict"] = True
        with self.assertRaises(DatasetError):
            load_jsonl(write(records))


if __name__ == "__main__":
    unittest.main()
