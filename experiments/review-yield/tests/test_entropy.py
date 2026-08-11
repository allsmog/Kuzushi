"""Entropy, hand-checkable. Design §13.1."""

import unittest

from support import tiny_rows

from kuzushi_review_yield.entropy import entropy


class EntropyTest(unittest.TestCase):
    def test_empty_is_zero(self):
        self.assertEqual(entropy([]), 0.0)

    def test_pure_is_zero(self):
        self.assertEqual(entropy([1, 1, 1, 1]), 0.0)

    def test_pure_is_positive_zero_not_negative_zero(self):
        # A "-0.0" would serialize into a model artifact and fail the schema's
        # lower bound on entropyBits.
        self.assertEqual(repr(entropy([0, 0, 0])), "0.0")

    def test_balanced_is_one(self):
        self.assertAlmostEqual(entropy([0, 1]), 1.0, places=12)

    def test_tiny_fixture_parent_entropy(self):
        # 4 positive / 6 negative, the design's own 40/60 illustration.
        self.assertAlmostEqual(
            entropy([row.label for row in tiny_rows()]), 0.970951, places=6
        )

    def test_class_weights_rebalance_a_skewed_population(self):
        labels = [1] + [0] * 9
        weights = {1: 10 / 2, 0: 10 / 18}
        self.assertAlmostEqual(entropy(labels, weights), 1.0, places=12)


if __name__ == "__main__":
    unittest.main()
