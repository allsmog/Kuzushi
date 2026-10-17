"""Bounded direct configuration inspection with a selected directory and no Git writes."""
import hashlib
import json
import sqlite3
import sys
import time
from pathlib import Path

from scan_source_settlement import ledger, save


def source(root):
    return {name:hashlib.sha256((root / name).read_bytes()).hexdigest()
        for name in ["Dockerfile","selected/Dockerfile","selected/Dockerfile.oversized"]
        if (root / name).is_file()}


def prepare(root, evidence):
    for name in ["app.py","config.env"]:
        (root / name).unlink(missing_ok=True)
    selected = root / "selected"
    selected.mkdir()
    (selected / "Dockerfile").write_text("FROM owned:latest\nUSER nobody\n# Owned inert policy example\n")
    (selected / "Dockerfile.oversized").write_text("#" * 2048)
    (selected / "cycle").symlink_to(selected, target_is_directory=True)
    (root / "Dockerfile").write_text("FROM excluded:latest\nUSER root\n")
    command = "run iac-scan:scan " + json.dumps({"target":"selected",
        "maxFileBytes":1024,"maxEntries":100,"maxTotalBytes":2048})
    (evidence / "scan-command.txt").write_text(command)
    save(evidence,"expected-source",source(root))


def repair(root, evidence):
    (root / "selected/Dockerfile.oversized").unlink()
    save(evidence,"expected-source",source(root))


def results(root):
    values = {}
    for path in (root / ".kuzushi/v3/runs").glob("*/run.json"):
        if json.loads(path.read_text()).get("tool") != "iac-scan:scan":
            continue
        result = path.with_name("result.json")
        if result.is_file():
            values[path.parent.name] = json.loads(result.read_text())
    return values


def inspect(root, evidence, stage):
    assert source(root) == json.loads((evidence / "expected-source.json").read_text())
    assert (root / "selected/cycle").is_symlink()
    values = results(root)
    expected = {"partial":(1,0),"deferred":(1,1),"report":(1,1),"complete":(2,1),"restarted":(2,1)}[stage]
    counts = ledger(root)
    assert (len(values),counts["review_decisions"]) == expected
    assert counts["finding_observations"] == expected[0]
    assert counts["findingStatuses"] == ["open"]
    assert counts["investigation_call_reservations"] == counts["investigation_work_attempts"] == 0
    assert sum(v["status"] == "partial" for v in values.values()) == 1
    for run,value in values.items():
        data = value["data"]
        assert data["count"] == 1 and data["sourceCheckCurrent"] is True
        assert Path(data["target"]).resolve() == root / "selected"
        assert data["coreFindings"][0]["file_path"] == "selected/Dockerfile"
        assert data["persisted"]["runId"] == run and counts["runStatuses"][run] == value["status"]
        assert len(data["treeHash"]) == len(data["snapshotHash"]) == 64
        assert data["inspection"]["symlinksExcluded"] == 1
        assert data["inspection"]["bytesRead"] == (root / "selected/Dockerfile").stat().st_size
        assert data["filesSkipped"] == (1 if value["status"] == "partial" else 0)
    save(evidence,stage+"-check",{"statuses":{run:v["status"] for run,v in values.items()},
        "selectedDirectory":"selected","excludedParentUnchanged":True,"sourceCheckCurrent":True,
        "counts":counts,"liveProviderRequests":0,"targetSourceExecuted":False,"scriptedReviewControls":True})


def wait_for_inspection(root, evidence, stage):
    deadline = time.monotonic() + 20
    while True:
        try:
            inspect(root,evidence,stage)
            return
        except (AssertionError,FileNotFoundError,json.JSONDecodeError,sqlite3.OperationalError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.1)


if __name__ == "__main__":
    root,evidence,stage = Path(sys.argv[1]).resolve(),Path(sys.argv[2]).resolve(),sys.argv[3]
    if stage == "prepare": prepare(root,evidence)
    elif stage == "repair": repair(root,evidence)
    else: wait_for_inspection(root,evidence,stage)
