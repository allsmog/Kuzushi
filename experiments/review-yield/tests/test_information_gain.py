"""Information gain and threshold candidates against hand-computed values."""

import unittest

from support import tiny_rows

from kuzushi_review_yield.entropy import (
    candidate_numeric_thresholds,
    gains_are_tied,
    information_gain,
)


def label_of(row):
    return row.label


class InformationGainTest(unittest.TestCase):
    def setUp(self):
        self.rows = tiny_rows()

    def gain(self, predicate):
        return information_gain(self.rows, label_of, predicate)

    def test_source_sink_linked_gain(self):
        # true branch (3+,1-) H=0.811278, false branch (1+,5-) H=0.650022,
        # weighted 0.714525, gain 0.970951 - 0.714525.
        self.assertAlmostEqual(
            self.gain(lambda row: row.features["sourceSinkLinked"]), 0.256426, places=6
        )

    def test_candidate_thresholds_label_change_midpoints(self):
        thresholds = candidate_numeric_thresholds(
            self.rows, lambda row: row.features["evidenceCount"], label_of
        )
        self.assertEqual(thresholds, [1.5, 2.5])

    def test_evidence_count_gains(self):
        self.assertAlmostEqual(
            self.gain(lambda row: row.features["evidenceCount"] <= 2.5), 0.556780, places=6
        )
        self.assertAlmostEqual(
            self.gain(lambda row: row.features["evidenceCount"] <= 1.5), 0.419973, places=6
        )

    def test_path_bucket_one_vs_rest_gains(self):
        expected = {"application": 0.0, "test": 0.281291, "vendor": 0.321928}
        for bucket, gain in expected.items():
            with self.subTest(bucket=bucket):
                self.assertAlmostEqual(
                    self.gain(lambda row, b=bucket: row.features["pathBucket"] == b),
                    gain,
                    places=6,
                )

    def test_degenerate_split_zero_gain(self):
        # Everything goes one way: nothing is separated, so the gain is exactly
        # zero rather than a near-zero float that could win a tie-break.
        self.assertEqual(self.gain(lambda _row: True), 0.0)
        self.assertEqual(self.gain(lambda _row: False), 0.0)

    def test_empty_rows_gain_zero(self):
        self.assertEqual(information_gain([], label_of, lambda _row: True), 0.0)

    def test_gain_equality_epsilon(self):
        self.assertTrue(gains_are_tied(0.256426, 0.256426 + 1e-13))
        self.assertFalse(gains_are_tied(0.256426, 0.256427))


if __name__ == "__main__":
    unittest.main()
