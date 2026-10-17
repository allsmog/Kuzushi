"""Missing installed scanner is a failed action, never clean repository evidence."""
import json
import shutil
import sqlite3
import sys
import time
from pathlib import Path

from cargo_audit import hashes, save
from secret_settings import ledger as open_ledger


def prepare(root, evidence, home):
    assert shutil.which("govulncheck") is None, "This journey requires an actually missing scanner; PATH is not masked."
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "go.mod").write_text("module owned.invalid/metadata\n\ngo 1.23\n")
    (root / "README.md").write_text("# Owned inert metadata\nNo package loading or execution is included.\n")
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text("")
    save(evidence, "source-before", hashes(root))


def inspect(root, evidence, stage):
    assert hashes(root) == json.loads((evidence / "source-before.json").read_text())
    values = []
    for path in (root / ".kuzushi/v3/runs").glob("*/run.json"):
        record = json.loads(path.read_text())
        if record.get("tool") == "govulncheck:scan":
            values.append((path.parent, record))
    assert len(values) == 1
    folder, record = values[0]
    value = json.loads((folder / "result.json").read_text())
    assert record["status"] == value["status"] == "failed"
    assert "binary not found" in value["output"]
    assert "go install" in value["output"]
    assert not value["data"].get("persisted") and "sourceCheckCurrent" not in value["data"]
    assert not (folder / "findings.json").exists()
    with open_ledger(root, evidence) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        counts = {name: db.execute("select count(*) from " + name).fetchone()[0] if name in tables else 0
            for name in ["finding_observations", "review_decisions", "investigation_call_reservations", "investigation_work_attempts"]}
        counts["findingStatuses"] = [row[0] for row in db.execute("select current_status from stable_findings")]
    for key in ["finding_observations", "review_decisions", "investigation_call_reservations", "investigation_work_attempts"]:
        assert counts[key] == 0
    assert counts["findingStatuses"] == []
    (evidence / "failed-replay.txt").write_text("replay " + folder.name)
    save(evidence, stage + "-check", {"status": "failed", "counts": counts,
        "scannerAvailable": False, "sourceUnchanged": True, "liveProviderRequests": 0,
        "targetSourceExecuted": False, "goPackageLoaded": False})


def wait(root, evidence, stage):
    deadline = time.monotonic() + 25
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
    if stage == "prepare": prepare(root, evidence, Path(sys.argv[4]).resolve())
    else: wait(root, evidence, stage)
