"""Baselines. Design §16.5."""

import unittest

from support import labeled_row, synthetic_rows, tiny_rows

from kuzushi_review_yield.baselines import (
    all_baselines,
    fit_logistic,
    majority_class,
    restricted_static_impact,
    severity_only,
    sklearn_comparison_tree,
    static_proof_severity,
)
from kuzushi_review_yield.dataset import partition_complete_rows
from kuzushi_review_yield.evaluate import pr_auc
from kuzushi_review_yield.id3 import default_feature_schema

from support import has_module

SCHEMA = default_feature_schema()


class OrderingBaselineTest(unittest.TestCase):
    def test_severity_orderings(self):
        critical = labeled_row(1, severityRank=0)
        low = labeled_row(1, severityRank=4)
        self.assertGreater(severity_only(critical), severity_only(low))

    def test_static_proof_beats_severity_in_the_ordering(self):
        confirmed_low = labeled_row(1, staticProofState="statically_confirmed", severityRank=4)
        signal_critical = labeled_row(1, staticProofState="signal_only", severityRank=0)
        self.assertGreater(
            static_proof_severity(confirmed_low), static_proof_severity(signal_critical)
        )

    def test_rejected_proof_sorts_last(self):
        rejected = labeled_row(0, staticProofState="statically_rejected", severityRank=0)
        signal = labeled_row(0, staticProofState="signal_only", severityRank=5)
        self.assertLess(static_proof_severity(rejected), static_proof_severity(signal))

    def test_restricted_static_impact_deterministic(self):
        row = labeled_row(1, sourceSinkLinked=True, hasExploitScenario=True)
        self.assertEqual(restricted_static_impact(row), restricted_static_impact(row))
        self.assertGreater(restricted_static_impact(row), restricted_static_impact(labeled_row(1)))

    def test_majority_class_is_the_training_base_rate(self):
        rows = tiny_rows()
        self.assertAlmostEqual(majority_class(rows)(rows[0]), 0.4, places=12)


class LogisticTest(unittest.TestCase):
    def setUp(self):
        complete, _ = partition_complete_rows(synthetic_rows())
        self.rows = complete[:200]

    def test_logistic_deterministic(self):
        first = fit_logistic(self.rows, SCHEMA, epochs=50)
        second = fit_logistic(self.rows, SCHEMA, epochs=50)
        self.assertEqual(first.weights, second.weights)
        self.assertEqual(first.bias, second.bias)

    def test_logistic_separates_planted_signal(self):
        model = fit_logistic(self.rows, SCHEMA, epochs=400)
        scored = [(row, model.probability(row)) for row in self.rows]
        base_rate = sum(row.label for row in self.rows) / len(self.rows)
        self.assertGreater(pr_auc(scored), base_rate + 0.15)

    def test_probabilities_stay_in_the_unit_interval(self):
        model = fit_logistic(self.rows, SCHEMA, epochs=100)
        for row in self.rows[:50]:
            self.assertTrue(0.0 <= model.probability(row) <= 1.0)

    def test_zero_variance_numerics_are_dropped(self):
        model = fit_logistic(tiny_rows(), SCHEMA, epochs=10)
        self.assertNotIn("runCount", model.encoder.columns)
        self.assertIn("evidenceCount", model.encoder.columns)

    def test_all_baselines_are_named_and_callable(self):
        baselines = all_baselines(self.rows, SCHEMA)
        self.assertEqual(
            sorted(baselines),
            [
                "logistic_regression",
                "majority_class",
                "restricted_static_impact",
                "severity_only",
                "static_proof_severity",
            ],
        )
        for name, scorer in baselines.items():
            with self.subTest(baseline=name):
                self.assertIsInstance(scorer(self.rows[0]), float)


class SklearnComparisonTest(unittest.TestCase):
    @unittest.skipUnless(has_module("sklearn"), "optional scikit-learn not installed")
    def test_sklearn_comparison_returns_shape_and_brier(self):
        complete, _ = partition_complete_rows(synthetic_rows())
        result = sklearn_comparison_tree(
            complete[:180], complete[180:], SCHEMA, max_depth=3, min_samples_leaf=20
        )
        self.assertEqual(sorted(result), ["brier", "depth", "leaves"])
        self.assertLessEqual(result["depth"], 3)
        self.assertTrue(0.0 <= result["brier"] <= 1.0)

    @unittest.skipIf(has_module("sklearn"), "scikit-learn is installed")
    def test_absent_sklearn_gives_an_actionable_error(self):
        with self.assertRaises(RuntimeError) as caught:
            sklearn_comparison_tree(tiny_rows(), tiny_rows(), SCHEMA, max_depth=2, min_samples_leaf=1)
        self.assertIn("setup-venv.sh", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
