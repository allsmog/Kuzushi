"""The committed synthetic corpus is reproducible and carries no real data."""

import json
import unittest

from support import SYNTHETIC, SYNTHETIC_MANIFEST, synthetic_rows

from kuzushi_review_yield.dataset import (
    CATEGORICAL_VOCABULARY,
    EXPORTED_CUTOFF_QUALITY,
    gen_synthetic_corpus,
    partition_complete_rows,
    synthetic_manifest,
)
from kuzushi_review_yield.hashing import canonical_json_bytes

WALL_CLOCK_MARKERS = ("createdAt", "timestamp", "decidedAt", "updatedAt", "date")


class SyntheticCorpusTest(unittest.TestCase):
    def setUp(self):
        self.records = gen_synthetic_corpus()

    def test_seed_6601_byte_identical_to_fixture(self):
        rebuilt = b"".join(canonical_json_bytes(record) + b"\n" for record in self.records)
        self.assertEqual(rebuilt, SYNTHETIC.read_bytes())

    def test_manifest_digest_is_reproducible(self):
        committed = json.loads(SYNTHETIC_MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(synthetic_manifest(self.records), committed)
        self.assertTrue(committed["datasetDigest"].startswith("blake3:"))

    def test_a_different_seed_gives_a_different_corpus(self):
        self.assertNotEqual(gen_synthetic_corpus(seed=1), self.records)

    def test_both_classes_all_vocab_values_present(self):
        rows = synthetic_rows()
        self.assertEqual({row.label for row in rows}, {0, 1})
        for feature, vocabulary in CATEGORICAL_VOCABULARY.items():
            with self.subTest(feature=feature):
                present = {row.features[feature] for row in rows}
                self.assertEqual(present, set(vocabulary))

    def test_both_exported_cutoff_qualities_present(self):
        self.assertEqual(
            {row.cutoff_quality for row in synthetic_rows()}, set(EXPORTED_CUTOFF_QUALITY)
        )

    def test_no_wall_clock_fields(self):
        raw = SYNTHETIC.read_text(encoding="utf-8")
        for marker in WALL_CLOCK_MARKERS:
            with self.subTest(marker=marker):
                self.assertNotIn(marker, raw)

    def test_corpus_is_large_enough_for_the_dataset_gate(self):
        rows = synthetic_rows()
        positives = sum(row.label for row in rows)
        self.assertGreaterEqual(len(rows), 200)
        self.assertGreaterEqual(min(positives, len(rows) - positives), 50)

    def test_incomplete_rows_exist_so_the_exclusion_path_is_exercised(self):
        complete, incomplete = partition_complete_rows(synthetic_rows())
        self.assertGreater(len(incomplete), 0)
        self.assertGreater(len(complete), len(incomplete))

    def test_identifiers_are_salted_digests_not_paths(self):
        for record in self.records[:20]:
            self.assertRegex(record["identityGroup"], r"^blake3:[0-9a-f]{64}$")
            self.assertRegex(record["repositoryGroup"], r"^blake3:[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
