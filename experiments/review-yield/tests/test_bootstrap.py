"""Paired bootstrap intervals. Design §16.8."""

import unittest

from kuzushi_review_yield.bootstrap import Interval, paired_bootstrap_delta


def mean_delta(sample):
    return sum(sample) / len(sample) if sample else 0.0


class BootstrapTest(unittest.TestCase):
    def setUp(self):
        self.groups = [0.1 * index - 0.5 for index in range(40)]

    def test_seeded_reproducible(self):
        first = paired_bootstrap_delta(self.groups, mean_delta, replicates=200, seed=6601)
        second = paired_bootstrap_delta(self.groups, mean_delta, replicates=200, seed=6601)
        self.assertEqual(first, second)

    def test_different_seed_gives_a_different_interval(self):
        first = paired_bootstrap_delta(self.groups, mean_delta, replicates=200, seed=6601)
        second = paired_bootstrap_delta(self.groups, mean_delta, replicates=200, seed=1)
        self.assertEqual(first.point, second.point)
        self.assertNotEqual((first.low, first.high), (second.low, second.high))

    def test_interval_contains_point_delta(self):
        result = paired_bootstrap_delta(self.groups, mean_delta, replicates=400, seed=6601)
        self.assertLessEqual(result.low, result.point)
        self.assertLessEqual(result.point, result.high)

    def test_constant_improvement_has_a_lower_bound_above_zero(self):
        result = paired_bootstrap_delta([0.2] * 30, mean_delta, replicates=200, seed=6601)
        self.assertTrue(result.excludes_zero_from_below())

    def test_no_effect_does_not_clear_the_gate(self):
        result = paired_bootstrap_delta([0.0] * 30, mean_delta, replicates=200, seed=6601)
        self.assertFalse(result.excludes_zero_from_below())

    def test_empty_groups_return_a_zero_interval(self):
        self.assertEqual(paired_bootstrap_delta([], mean_delta), Interval(0.0, 0.0, 0.0))

    def test_as_json_uses_report_keys(self):
        result = paired_bootstrap_delta([0.2] * 5, mean_delta, replicates=50, seed=1)
        self.assertEqual(sorted(result.as_json()), ["high95", "low95", "point"])


if __name__ == "__main__":
    unittest.main()
