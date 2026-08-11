"""Review-budget metrics, the within-band policy, and the gates."""

import unittest

from support import labeled_row, tiny_rows

from kuzushi_review_yield.evaluate import (
    FAIL,
    NOT_APPLICABLE,
    PASS,
    active_leaves,
    band_key,
    band_report,
    baseline_queue,
    budget_size,
    dataset_gates,
    model_gates,
    pr_auc,
    precision_at,
    queue_metrics,
    recall_at,
    simulate_within_band_queue,
)
from kuzushi_review_yield.id3 import build_category_map, default_feature_schema, fit_id3

SCHEMA = default_feature_schema()


def tiny_tree_and_categories(rows):
    tree = fit_id3(
        rows, SCHEMA, max_depth=2, min_samples_leaf=1, min_gain=0.0, rare_category_min_count=1
    )
    return tree, build_category_map(rows, SCHEMA, 1)


class BudgetMetricTest(unittest.TestCase):
    def setUp(self):
        self.rows = tiny_rows()
        tree, categories = tiny_tree_and_categories(self.rows)
        from kuzushi_review_yield.id3 import score_rows

        self.scored = list(zip(self.rows, score_rows(tree, self.rows, categories)))

    def test_budget_size_reviews_at_least_one(self):
        self.assertEqual(budget_size(10, 0.20), 2)
        self.assertEqual(budget_size(3, 0.10), 1)
        self.assertEqual(budget_size(0, 0.20), 0)

    def test_precision_recall_at_20_hand_case(self):
        # The two top-scored rows are both confirmed; 4 positives in total.
        self.assertAlmostEqual(precision_at(self.scored, 0.20), 1.0, places=12)
        self.assertAlmostEqual(recall_at(self.scored, 0.20), 0.5, places=12)

    def test_pr_auc_hand_case(self):
        # All four positives rank above every negative: average precision 1.0.
        self.assertAlmostEqual(pr_auc(self.scored), 1.0, places=12)

    def test_pr_auc_interleaved_hand_case(self):
        # Ranked +,-,+,-: (1/1 + 2/3) / 2.
        scored = [
            (labeled_row(1, evidenceCount=1), 0.9),
            (labeled_row(0, evidenceCount=2), 0.8),
            (labeled_row(1, evidenceCount=3), 0.7),
            (labeled_row(0, evidenceCount=4), 0.6),
        ]
        self.assertAlmostEqual(pr_auc(scored), (1.0 + 2 / 3) / 2, places=12)

    def test_no_positives_gives_zero_recall_and_auc(self):
        scored = [(labeled_row(0, evidenceCount=index), 0.5) for index in range(4)]
        self.assertEqual(recall_at(scored, 0.5), 0.0)
        self.assertEqual(pr_auc(scored), 0.0)

    def test_ranking_ties_are_broken_deterministically(self):
        scored = [(row, 0.5) for row in self.rows]
        from kuzushi_review_yield.evaluate import rank

        self.assertEqual(
            [row.identity_group for row in rank(scored)],
            [row.identity_group for row in rank(list(reversed(scored)))],
        )


class WithinBandTest(unittest.TestCase):
    def setUp(self):
        # Two proof bands, each with two rows, so reordering has somewhere to go.
        self.rows = [
            labeled_row(0, staticProofState="statically_confirmed", evidenceCount=0),
            labeled_row(1, staticProofState="statically_confirmed", evidenceCount=6),
            labeled_row(0, staticProofState="signal_only", evidenceCount=1),
            labeled_row(1, staticProofState="signal_only", evidenceCount=7),
        ]
        self.tree, self.categories = tiny_tree_and_categories(tiny_rows())

    def test_within_band_never_crosses_band(self):
        queue = simulate_within_band_queue(
            self.rows, self.tree, self.categories, minimum_leaf_support=1
        )
        bands = [band_key(row) for row in queue]
        self.assertEqual(bands, sorted(bands))
        self.assertEqual(len(queue), len(self.rows))

    def test_eligible_band_is_reordered_by_score(self):
        queue = simulate_within_band_queue(
            self.rows, self.tree, self.categories, minimum_leaf_support=1
        )
        confirmed = [row for row in queue if row.features["staticProofState"] == "statically_confirmed"]
        self.assertEqual([row.label for row in confirmed], [1, 0])

    def test_ineligible_group_keeps_baseline_order(self):
        # A leaf-support floor no leaf can clear makes every band ineligible.
        queue = simulate_within_band_queue(
            self.rows, self.tree, self.categories, minimum_leaf_support=1000
        )
        self.assertEqual(queue, baseline_queue(self.rows))

    def test_band_report_explains_a_zero_delta(self):
        report = band_report(self.rows, self.tree, self.categories, minimum_leaf_support=1)
        self.assertEqual(report["bands"], 2)
        self.assertEqual(report["multiRowBands"], 2)
        self.assertEqual(report["reorderableBands"], 2)
        self.assertEqual(report["rowsInReorderableBands"], 4)

    def test_band_report_counts_no_room_when_support_is_unreachable(self):
        report = band_report(self.rows, self.tree, self.categories, minimum_leaf_support=1000)
        self.assertEqual(report["reorderableBands"], 0)

    def test_queue_metrics_read_position_as_score(self):
        queue = simulate_within_band_queue(
            self.rows, self.tree, self.categories, minimum_leaf_support=1
        )
        self.assertEqual(queue_metrics(queue)["precisionAt50"], 0.5)


class GateTest(unittest.TestCase):
    def test_small_corpus_fails_the_production_gates_honestly(self):
        gates = {gate.name: gate for gate in dataset_gates(tiny_rows(), incomplete=0)}
        self.assertEqual(gates["eligible_identities"].status, FAIL)
        self.assertEqual(gates["class_balance"].status, FAIL)
        self.assertEqual(gates["unique_identities"].status, PASS)
        self.assertEqual(gates["forbidden_field_check"].status, PASS)
        self.assertIn("10 eligible identities", gates["eligible_identities"].detail)

    def test_feature_completeness_is_reported_not_imputed(self):
        gates = {gate.name: gate for gate in dataset_gates(tiny_rows(), incomplete=7)}
        self.assertIn("7 of 17 rows", gates["feature_completeness_reported"].detail)

    def test_missing_interval_is_not_applicable_rather_than_passing(self):
        tree, _ = tiny_tree_and_categories(tiny_rows())
        gates = {
            gate.name: gate
            for gate in model_gates(
                tree,
                active_leaves=active_leaves(tree, 1),
                delta_precision_low=None,
                temporal_precision_delta=0.1,
                minimum_leaf_support=1,
            )
        }
        self.assertEqual(gates["bootstrap_improvement"].status, NOT_APPLICABLE)
        self.assertEqual(gates["tree_depth"].status, PASS)
        self.assertEqual(gates["temporal_direction"].status, PASS)

    def test_negative_temporal_direction_fails(self):
        tree, _ = tiny_tree_and_categories(tiny_rows())
        gates = {
            gate.name: gate
            for gate in model_gates(
                tree,
                active_leaves=active_leaves(tree, 1),
                delta_precision_low=-0.02,
                temporal_precision_delta=-0.05,
                minimum_leaf_support=1,
            )
        }
        self.assertEqual(gates["temporal_direction"].status, FAIL)
        self.assertEqual(gates["bootstrap_improvement"].status, FAIL)

    def test_active_leaves_excludes_under_supported_leaves(self):
        tree, _ = tiny_tree_and_categories(tiny_rows())
        self.assertEqual(active_leaves(tree, minimum_leaf_support=20), [])
        self.assertEqual(len(active_leaves(tree, minimum_leaf_support=1)), 3)


if __name__ == "__main__":
    unittest.main()
