"""Owned real-runtime admission refusal; never starts a model request."""
import hashlib
import json
import sys
from pathlib import Path

from approved_live_review import inspect_existing, verify
from live_investigation import FIXTURE, invariant
from preserved_live_review import CAMPAIGN, inspect_completed, verify as verify_completed


def snapshot_hash(root):
    path = root / ".kuzushi/context-snapshot.json"
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None


def seed(root, evidence):
    if completed_review_exists(root):
        inspect_completed(root, evidence)
    else:
        inspect_existing(root, evidence)
    (evidence / "accounting-before.json").write_text((evidence / "existing-check.json").read_text())
    (evidence / "context-before.json").write_text(json.dumps({"sha256":snapshot_hash(root)}) + "\n")
    (evidence / "unbound-command.txt").write_text('run context:build {"enrichment":true}')
    (evidence / "deterministic-command.txt").write_text('run context:build {"enrichment":false}')


def check(root, evidence, stage):
    invariant(root, evidence)
    if stage == "refused":
        assert snapshot_hash(root) == json.loads((evidence / "context-before.json").read_text())["sha256"]
    if completed_review_exists(root):
        verify_completed(root, evidence, stage)
    else:
        verify(root, evidence, stage)
    recorded = json.loads((evidence / (stage + "-check.json")).read_text())
    before = json.loads((evidence / "accounting-before.json").read_text())
    assert recorded["counts"] == before["counts"]
    assert recorded["committedCalls"] == before["committedCalls"] and recorded["unresolvedCalls"] == 0
    results = [json.loads(path.read_text()) for path in (root / ".kuzushi/v3/runs").glob("*/result.json")]
    if stage == "refused":
        refusals = [result for result in results if "approved investigation allowance before model work" in json.dumps(result)]
        assert refusals and all(result.get("status") == "blocked" for result in refusals)


def completed_review_exists(root):
    return (root / ".kuzushi/v3/campaigns" / CAMPAIGN / "queue.json").exists()


if __name__ == "__main__":
    root,evidence,stage = Path(sys.argv[1]).resolve(),Path(sys.argv[2]).resolve(),sys.argv[3]
    assert root == FIXTURE / "target"
    evidence.mkdir(parents=True,exist_ok=True)
    if stage == "seed": seed(root,evidence)
    else: check(root,evidence,stage)
