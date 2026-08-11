"""Temporal split, frozen manifest, and drift rejection. Design §16.1-§16.2."""

import tempfile
import unittest
from pathlib import Path

from support import labeled_row, synthetic_rows, tiny_rows

from kuzushi_review_yield.splits import (
    SplitError,
    freeze_manifest,
    group_holdouts,
    load_manifest,
    temporal_split,
    verify_manifest,
)


class TemporalSplitTest(unittest.TestCase):
    def setUp(self):
        self.rows = synthetic_rows()
        self.split = temporal_split(self.rows)

    def test_70_15_15_ordered_by_label_seq(self):
        self.assertEqual(len(self.split.train), int(len(self.rows) * 0.70))
        self.assertEqual(len(self.split.validation), int(len(self.rows) * 0.15))
        self.assertEqual(
            len(self.split.train) + len(self.split.validation) + len(self.split.test),
            len(self.rows),
        )

    def test_folds_do_not_overlap_in_time(self):
        newest_train = max(row.label_seq for row in self.split.train)
        oldest_validation = min(row.label_seq for row in self.split.validation)
        newest_validation = max(row.label_seq for row in self.split.validation)
        oldest_test = min(row.label_seq for row in self.split.test)
        self.assertLess(newest_train, oldest_validation)
        self.assertLess(newest_validation, oldest_test)

    def test_folds_are_disjoint(self):
        ids = [row.example_id for fold in
               (self.split.train, self.split.validation, self.split.test) for row in fold]
        self.assertEqual(len(ids), len(set(ids)))

    def test_split_is_deterministic(self):
        self.assertEqual(temporal_split(self.rows).manifest(), self.split.manifest())
        self.assertEqual(temporal_split(list(reversed(self.rows))).manifest(), self.split.manifest())

    def test_manifest_freeze_and_verify(self):
        with tempfile.TemporaryDirectory() as directory:
            path = freeze_manifest(self.split.manifest(), Path(directory))
            reloaded = load_manifest(path)
            self.assertEqual(reloaded, self.split.manifest())
            verify_manifest(reloaded, temporal_split(self.rows))

    def test_verify_rejects_membership_drift(self):
        frozen = self.split.manifest()
        drifted = temporal_split(self.rows[:-1])
        with self.assertRaises(SplitError) as caught:
            verify_manifest(frozen, drifted)
        self.assertIn("drift", str(caught.exception))

    def test_tiny_fixture_split_shape(self):
        split = temporal_split(tiny_rows())
        self.assertEqual([len(split.train), len(split.validation), len(split.test)], [7, 1, 2])


class GroupHoldoutTest(unittest.TestCase):
    def test_small_groups_are_skipped(self):
        rows = [labeled_row(index % 2, evidenceCount=index) for index in range(30)]
        holdouts = list(group_holdouts(rows, lambda row: row.repository_group, min_size=20))
        self.assertEqual(holdouts, [])

    def test_holdout_train_excludes_the_group(self):
        rows = synthetic_rows()
        found = list(group_holdouts(rows, lambda row: row.repository_group, min_size=20))
        self.assertTrue(found)
        for group, train, held_out in found:
            self.assertTrue(all(row.repository_group != group for row in train))
            self.assertTrue(all(row.repository_group == group for row in held_out))
            self.assertEqual(len(train) + len(held_out), len(rows))


if __name__ == "__main__":
    unittest.main()
