"""Owned relationship review fixture. Real writer, no provider or source execution."""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from rejected_context import execute
from secret_settings import ledger


def prepare(root, evidence):
    env = dict(os.environ, KUZUSHI_BULK_RELATIONSHIP_FIXTURE_OUT=str(root))
    result = subprocess.run([os.environ["KUZUSHI_BULK_RELATIONSHIP_TEST_BIN"], "--exact",
        "app::relationships::bulk::tests::fixture::prepare_native_bulk_relationship_fixture", "--nocapture"],
        env=env, capture_output=True, text=True, timeout=30, check=True)
    (evidence / "preparation.log").write_text(result.stdout + result.stderr)
    receipt = json.loads((root / ".kuzushi/bulk-fixture.json").read_text())
    assert receipt["findingsAreSynthetic"] and not receipt["sourceExecuted"]
    assert receipt["providerRequests"] == 0 and len(receipt["relationships"]) == 3
    (evidence / "source-before.sha256").write_text(hashlib.sha256((root / "hello.txt").read_bytes()).hexdigest())
    (evidence / "accept-note.txt").write_text("Reviewed the labeled greeting pairs.\nOnly grouping is accepted; finding verdicts remain independent.")
    (evidence / "unlink-note.txt").write_text("Keep all labeled observations separate after relationship review.")
    verify(root, evidence, "proposed")


def stale(root, evidence):
    rows = execute(root, Path(os.environ["HOME"]), evidence, "before-stale", "findings:relationships", {})["rows"]
    chosen = rows[-1]
    execute(root, Path(os.environ["HOME"]), evidence, "concurrent-single", "findings:relationship", {
        "id": chosen["id"], "state": "rejected", "note": "Separate explicit fixture review to stale the held selection", "expectedRevision": chosen["revision"]})
    verify(root, evidence, "stale")


def verify(root, evidence, stage):
    home = Path(os.environ["HOME"])
    rows = execute(root, home, evidence, "relationships-" + stage, "findings:relationships", {})["rows"]
    states = sorted(row["state"] for row in rows)
    if stage in ["proposed", "pending"]: expected, batches, groups = ["proposed"] * 3, 0, 4
    elif stage == "accepted": expected, batches, groups = ["accepted"] * 3, 1, 1
    elif stage == "stale": expected, batches, groups = ["accepted", "accepted", "rejected"], 1, 2
    else: expected, batches, groups = ["removed"] * 3, 2, 4
    assert states == expected, states
    original = json.loads((root / ".kuzushi/bulk-fixture.json").read_text())["relationships"]
    endpoints = {row["id"]: (row["from"], row["to"]) for row in original}
    assert all(endpoints[row["id"]] == (row["from"], row["to"]) for row in rows)
    page = execute(root, home, evidence, "groups-" + stage, "findings:groups", {})
    assert (page["totalFindings"], page["totalGroups"]) == (4, groups)
    with ledger(root, evidence) as db:
        assert db.execute("select count(*) from finding_observations").fetchone()[0] == 4
        assert db.execute("select count(*) from review_decisions").fetchone()[0] == 0
        assert db.execute("select count(*) from rekey_edges").fetchone()[0] == 0
        assert db.execute("select count(*) from audit_events where subject='finding-relationship-batch-v1'").fetchone()[0] == batches
    assert hashlib.sha256((root / "hello.txt").read_bytes()).hexdigest() == (evidence / "source-before.sha256").read_text()
    (evidence / (stage + "-check.json")).write_text(json.dumps({"stage": stage, "states": states, "atomicBatchEvents": batches,
        "groups": groups, "findings": 4, "observations": 4, "findingDecisions": 0, "rekeys": 0,
        "providerRequests": 0, "sourceExecuted": False, "sourceUnchanged": True}, indent=2) + "\n")


if __name__ == "__main__":
    action, target, output = sys.argv[1:]
    root, evidence = Path(target).resolve(), Path(output).resolve()
    if action == "prepare": prepare(root, evidence)
    elif action == "stale-write": stale(root, evidence)
    else: verify(root, evidence, action)
