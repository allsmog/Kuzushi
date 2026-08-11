"""The hand-verified tree. Every expected number is in `fixtures/README` terms:

    root  evidenceCount <= 2.5   gain 0.556780
    right pure leaf (3+,0-)      Jeffreys 3.5/4   = 0.875
    left  pathBucket == vendor   gain 0.591673
          vendor leaf (1+,0-)    Jeffreys 1.5/2   = 0.75
          other  leaf (0+,6-)    Jeffreys 0.5/7   = 0.071429
"""

import unittest

from support import labeled_row, tiny_rows

from kuzushi_review_yield.id3 import (
    accuracy,
    alpha_sequence,
    build_category_map,
    default_feature_schema,
    fit_id3,
    leaves,
    prune,
    render_tree,
    tree_depth,
)

FULL_SCHEMA = default_feature_schema()


def fit(rows, schema=None, **overrides):
    options = dict(max_depth=2, min_samples_leaf=1, min_gain=0.0, rare_category_min_count=1)
    options.update(overrides)
    return fit_id3(rows, schema or FULL_SCHEMA, **options)


class Id3FixtureTest(unittest.TestCase):
    def setUp(self):
        self.rows = tiny_rows()
        self.tree = fit(self.rows)
        self.categories = build_category_map(self.rows, FULL_SCHEMA, 1)

    def test_root_split_is_evidence_count_2_5(self):
        self.assertEqual(self.tree.split.feature, "evidenceCount")
        self.assertEqual(self.tree.split.kind, "numeric")
        self.assertEqual(self.tree.split.threshold, 2.5)
        self.assertAlmostEqual(self.tree.gain_bits, 0.556780, places=6)

    def test_left_child_splits_vendor_pure(self):
        left = self.tree.left
        self.assertEqual(left.split.feature, "pathBucket")
        self.assertEqual(left.split.category, "vendor")
        self.assertAlmostEqual(left.gain_bits, 0.591673, places=6)
        self.assertTrue(left.left.is_leaf and left.right.is_leaf)

    def test_leaf_counts_smoothed_rates(self):
        self.assertEqual(
            (self.tree.right.positive_count, self.tree.right.negative_count), (3, 0)
        )
        self.assertAlmostEqual(self.tree.right.smoothed_rate, 0.875, places=6)
        self.assertAlmostEqual(self.tree.left.left.smoothed_rate, 0.75, places=6)
        self.assertAlmostEqual(self.tree.left.right.smoothed_rate, 0.071429, places=6)

    def test_pure_leaf_does_not_claim_certainty(self):
        # Three positives and no negatives must not read as 100%.
        self.assertLess(self.tree.right.smoothed_rate, 1.0)
        self.assertLess(self.tree.right.ci95[0], self.tree.right.smoothed_rate)

    def test_equal_gain_tie_break_by_feature_name(self):
        # hasSinkEvidence duplicates sourceSinkLinked, so both gains are
        # 0.256426; "h" sorts before "s".
        schema = default_feature_schema(["sourceSinkLinked", "hasSinkEvidence"])
        tree = fit(self.rows, schema, max_depth=1)
        self.assertEqual(tree.split.feature, "hasSinkEvidence")
        self.assertAlmostEqual(tree.gain_bits, 0.256426, places=6)

    def test_min_samples_leaf_stops_split(self):
        tree = fit(self.rows, min_samples_leaf=6)
        self.assertTrue(tree.is_leaf)
        self.assertEqual((tree.positive_count, tree.negative_count), (4, 6))

    def test_max_depth_stops(self):
        tree = fit(self.rows, max_depth=1)
        self.assertEqual(tree_depth(tree), 1)
        self.assertTrue(tree.left.is_leaf and tree.right.is_leaf)

    def test_min_gain_stops_split(self):
        self.assertTrue(fit(self.rows, min_gain=0.6).is_leaf)

    def test_refit_same_data_identical_tree(self):
        self.assertEqual(render_tree(fit(self.rows)), render_tree(fit(self.rows)))

    def test_refit_reordered_rows_identical_tree(self):
        shuffled = list(reversed(self.rows))
        self.assertEqual(render_tree(fit(shuffled)), render_tree(self.tree))

    def test_permissive_tree_overfits_vs_pruned(self):
        rows = _noisy_rows()
        permissive = fit_id3(
            rows, FULL_SCHEMA, max_depth=12, min_samples_leaf=1, min_gain=0.0
        )
        shallow = fit_id3(rows, FULL_SCHEMA, max_depth=1, min_samples_leaf=8, min_gain=0.0)
        categories = build_category_map(rows, FULL_SCHEMA, 5)
        # The permissive tree buys training accuracy with leaves that hold one
        # row each — the shape of overfitting, not evidence about new data.
        self.assertGreater(
            accuracy(permissive, rows, categories), accuracy(shallow, rows, categories)
        )
        self.assertGreaterEqual(len(leaves(permissive)), 4 * len(leaves(shallow)))
        self.assertEqual(min(leaf.support for leaf in leaves(permissive)), 1)

    def test_ccp_prune_collapses_subtree_at_large_alpha(self):
        alphas = alpha_sequence(self.tree)
        self.assertEqual(alphas[0], 0.0)
        self.assertEqual(alphas, sorted(alphas))
        self.assertTrue(prune(self.tree, alphas[-1]).is_leaf)
        self.assertEqual(render_tree(prune(self.tree, 0.0)), render_tree(self.tree))

    def test_rare_categories_fold_into_other(self):
        # vendor appears twice; at the default threshold of 5 it is not its own
        # category any more, so the vendor split disappears.
        tree = fit(self.rows, rare_category_min_count=5)
        categories = build_category_map(self.rows, FULL_SCHEMA, 5)
        self.assertEqual(categories["pathBucket"]["vendor"], "other")
        self.assertNotEqual(
            (tree.left.split.category if not tree.left.is_leaf else None), "vendor"
        )

    def test_incomplete_row_is_rejected_not_imputed(self):
        rows = self.rows + [labeled_row(1, maxEvidenceConfidence=None)]
        with self.assertRaises(ValueError) as caught:
            fit(rows)
        self.assertIn("maxEvidenceConfidence", str(caught.exception))


def _noisy_rows():
    """Two rows per evidence count with contradictory labels: memorizable only
    by a tree deep enough to isolate individual rows."""
    rows = []
    for index in range(8):
        rows.append(labeled_row(index % 2, evidenceCount=index, preconditionCount=index))
        rows.append(labeled_row(1 - index % 2, evidenceCount=index, preconditionCount=index + 8))
    return rows


if __name__ == "__main__":
    unittest.main()
