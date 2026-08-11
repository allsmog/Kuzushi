"""One durable identity contributes exactly one example (ADR-6)."""

import json
import tempfile
import unittest
from pathlib import Path

from support import tiny_records

from kuzushi_review_yield.dataset import DatasetError, load_jsonl
from kuzushi_review_yield.hashing import canonical_json_bytes


def write(records):
    handle = tempfile.NamedTemporaryFile("wb", suffix=".jsonl", delete=False)
    handle.write(b"".join(canonical_json_bytes(record) + b"\n" for record in records))
    handle.close()
    return Path(handle.name)


class IdentityUniquenessTest(unittest.TestCase):
    def test_duplicate_identity_group_rejected(self):
        records = tiny_records()
        duplicate = json.loads(json.dumps(records[3]))
        duplicate["exampleId"] = records[0]["exampleId"].replace("blake3:a", "blake3:b")
        duplicate["labelEvent"]["seq"] += 300
        duplicate["featureCutoffSeq"] += 300
        duplicate["anchorObservation"]["seq"] += 300
        records.append(duplicate)
        with self.assertRaises(DatasetError) as caught:
            load_jsonl(write(records))
        self.assertIn("duplicate identityGroup", str(caught.exception))

    def test_distinct_identities_load(self):
        self.assertEqual(len(load_jsonl(write(tiny_records()))), 10)

    def test_leakage_guard_rejects_cutoff_at_or_after_the_decision(self):
        records = tiny_records()
        records[0]["featureCutoffSeq"] = records[0]["labelEvent"]["seq"]
        with self.assertRaises(DatasetError) as caught:
            load_jsonl(write(records))
        self.assertIn("anchor <= cutoff < label", str(caught.exception))

    def test_leakage_guard_rejects_anchor_after_cutoff(self):
        records = tiny_records()
        records[2]["anchorObservation"]["seq"] = records[2]["featureCutoffSeq"] + 1
        with self.assertRaises(DatasetError):
            load_jsonl(write(records))

    def test_verdict_and_class_must_agree(self):
        records = tiny_records()
        records[0]["labelEvent"]["class"] = 1
        with self.assertRaises(DatasetError) as caught:
            load_jsonl(write(records))
        self.assertIn("implies class", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
