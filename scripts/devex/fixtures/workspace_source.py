"""Owned child scans keep parent-owned source identity and honest phase guidance."""
import json
import sqlite3
import sys
import time
from pathlib import Path

import child_target_sources as child


def inspect_workspace_source(root, evidence, stage):
    expected = {"prepare": 1, "six": 6, "sast-run": 9,
        "reviewed": 9, "exported": 9, "restarted": 9}[stage]
    for name in ["client", "service"]:
        assert not (root / name / ".kuzushi").exists(), name
    claims = []
    for path in (root / ".kuzushi/v3/runs").glob("*/result.json"):
        output = json.loads(path.read_text())
        data = output.get("data", {})
        if not data.get("coreFindings"):
            continue
        assert output["status"] == "completed"
        assert data["sourceCheckCurrent"] is True
        if "manifestsScanned" in data:
            scope = data["phaseStages"][0]["scan"]["scope"]
            assert scope["target"] == data["target"]
            assert Path(scope["target"]).parent == root
        claims.append((path.parent.name, data["snapshotHash"], data["treeHash"]))
    assert len(claims) == expected
    assert len({row[2] for row in claims}) == 1
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=rw", uri=True) as db:
        db.execute("PRAGMA query_only=ON")
        roots = set()
        for run, snapshot, tree in claims:
            row = db.execute("select tree_hash,workspace_root_fingerprint from target_snapshots where snapshot_hash=?", (snapshot,)).fetchone()
            assert row and row[0] == tree, run
            roots.add(row[1])
    assert len(roots) == 1
    ledger = root / ".kuzushi/v3/workflow/phase-attempts.v2.jsonl"
    attempts = []
    if ledger.exists():
        attempts = [json.loads(line)["record"] for line in ledger.read_text().splitlines()]
        for value in attempts:
            assert value["event"] == "completed"
            assert value["phase"] == "scan" and value["target"] == str(root)
            identity = value["targetContentIdentity"]
            assert identity["kind"] == "indexed_snapshot"
            assert identity["tree_hash"] == claims[0][2]
    if stage != "prepare":
        assert len(attempts) == 5
    child.save(evidence, stage + "-workspace-source", {
        "actualNativeRuns": len(claims), "pendingScanResults": len(attempts),
        "allIdentitiesOwnedByParent": True, "noChildStateCreated": True,
        "sameWorkspaceTree": claims[0][2], "newProviderRequests": 0,
        "acceptedMap": False, "acceptedScan": False,
    })


def wait_for_workspace_source(root, evidence, stage):
    deadline = time.monotonic() + 20
    while True:
        try:
            inspect_workspace_source(root, evidence, stage)
            return
        except (AssertionError, FileNotFoundError, KeyError, json.JSONDecodeError, sqlite3.OperationalError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.1)


if __name__ == "__main__":
    root, evidence, home = (Path(value).resolve() for value in sys.argv[1:4])
    stage = sys.argv[4]
    if stage == "prepare":
        child.prepare(root, evidence, home)
    elif stage == "sast-run":
        child.sast(root, evidence, home)
    else:
        child.wait_for_inspection(root, evidence, stage)
    wait_for_workspace_source(root, evidence, stage)
