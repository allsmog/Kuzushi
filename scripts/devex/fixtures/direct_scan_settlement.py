"""Direct installed scanner settlement with planned inert edits and no model work."""
import json
import sqlite3
import sys
import time
from pathlib import Path

from scan_source_settlement import (
    ledger, prepare as prepare_scanner, prepare_drift, release_with_edit, save, source,
)


def prepare(root, evidence):
    prepare_scanner(root, evidence)
    command = "run semgrep:scan " + json.dumps({
        "binary": str(evidence / "owned-scanner.py"),
        "config": str(evidence / "owned-local-rules.yaml"),
        "jobs": 1, "timeoutMs": 30000,
    })
    (evidence / "scan-command.txt").write_text(command)


def results(root):
    values = {}
    for path in (root / ".kuzushi/v3/runs").glob("*/result.json"):
        value = json.loads(path.read_text())
        data = value.get("data", {})
        if data.get("persisted", {}).get("runId") == path.parent.name and "count" in data:
            values[path.parent.name] = value
    return values


def inspect(root, evidence, stage):
    assert source(root) == json.loads((evidence / "expected-source.json").read_text())
    values = results(root)
    completed = [(run, v) for run, v in values.items() if v.get("status") == "completed"]
    partial = [(run, v) for run, v in values.items() if v.get("status") == "partial"]
    expected = {"baseline": (1, 0, 0), "deferred": (1, 0, 1), "partial": (1, 1, 1),
        "partial-report": (1, 1, 1), "complete": (2, 1, 1), "restarted": (2, 1, 1)}[stage]
    counts = ledger(root)
    assert (len(completed), len(partial), counts["review_decisions"]) == expected
    assert counts["finding_observations"] == 1
    assert set(counts["findingStatuses"]) <= {"open", "stale"}
    if stage not in ["complete", "restarted"]:
        assert counts["findingStatuses"] == ["open"]
    assert sum(v["data"]["count"] for v in values.values()) == 1
    for run, value in values.items():
        data = value["data"]
        assert len(data["treeHash"]) == 64 and len(data["snapshotHash"]) == 64
        assert counts["runStatuses"][run] == value["status"]
        assert data["persisted"]["runId"] == run
        if value["status"] == "partial":
            assert data["count"] == 0 and "source changed" in json.dumps(value).lower()
    if len(completed) == 2:
        stable = next(v for _, v in completed if v["data"]["count"] == 0)
        assert stable["data"]["treeHash"] != partial[0][1]["data"]["treeHash"]
    save(evidence, stage + "-check", {"runIds": sorted(values), "completed": len(completed),
        "partial": len(partial), "providerCalls": 0, "installedLocalScanner": True,
        "scriptedReviewControls": True, "sourceExecuted": False, **counts})


def wait_for_inspection(root, evidence, stage):
    deadline = time.monotonic() + 20
    while True:
        try:
            inspect(root, evidence, stage)
            return
        except (AssertionError, FileNotFoundError, json.JSONDecodeError, sqlite3.OperationalError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.1)


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "prepare": prepare(root, evidence)
    elif stage == "prepare-drift": prepare_drift(root, evidence)
    elif stage == "release-with-edit": release_with_edit(root, evidence)
    elif stage == "stable": (evidence / "mode.txt").write_text("stable")
    else: wait_for_inspection(root, evidence, stage)
