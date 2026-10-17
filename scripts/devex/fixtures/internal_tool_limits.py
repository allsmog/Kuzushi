"""Inert comments and settings qualify contracts, not vulnerability detection."""
import json
import sqlite3
import sys
import time
from pathlib import Path

from cargo_audit import hashes, save
from secret_settings import ledger

PAIRS = [{"alloc": "owned_alloc", "free": "owned_free"}]


def prepare(root, evidence, home):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "broker").mkdir()
    (root / "broker/owned.cc").write_text(
        "// Owned inert token: DuplicateHandle. Never executed.\n" * 3)
    (root / "README.md").write_text(
        "# Owned comment-only fixture\nNo executable source or vulnerability is claimed.\n")
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text("")
    (evidence / "home.txt").write_text(str(home))
    (evidence / "pairs.txt").write_text(json.dumps(PAIRS))
    save(evidence, "source-before", hashes(root))


def options(evidence):
    home = Path((evidence / "home.txt").read_text())
    value = json.loads((home / ".kuzushi/v3/options.json").read_text())
    assert value["bindings"]["global/tool/uaf-hunt:hunt"]["allocFreePairs"] == PAIRS


def inspect(root, evidence, stage):
    assert hashes(root) == json.loads((evidence / "source-before.json").read_text())
    options(evidence)
    runs = [(p.parent, json.loads(p.read_text()))
            for p in (root / ".kuzushi/v3/runs").glob("*/run.json")]
    if stage == "options":
        assert not runs, "Editing options must not execute the UAF scanner"
        save(evidence, "options-check", {"structuredOptionSaved": True, "toolRuns": 0})
        return
    assert len(runs) == 1 and runs[0][1]["tool"] == "chrome-rce:scan"
    folder, run = runs[0]
    result = json.loads((folder / "result.json").read_text())
    assert run["status"] == result["status"] == "partial"
    assert result["data"]["count"] == len(result["data"]["findings"]) == 1
    assert result["data"]["inspection"] == {"maxFindings": 1, "findingLimitReached": True}
    assert "remaining source was not inspected" in result["output"]
    assert result["warnings"]
    persisted = result["data"]["persisted"]["runId"]
    with ledger(root, evidence) as db:
        assert db.execute("select status from run_states where run_id=?", (persisted,)).fetchone()[0] == "partial"
        assert db.execute("select count(*) from finding_observations").fetchone()[0] == 1
        tables = {r[0] for r in db.execute("select name from sqlite_master where type='table'")}
        for table in ["investigation_call_reservations", "investigation_work_attempts"]:
            assert table not in tables or db.execute("select count(*) from " + table).fetchone()[0] == 0
        decisions = [r[0] for r in db.execute("select decision_verdict from review_decisions")]
    assert decisions == ([] if stage == "partial" else ["deferred"])
    if stage in ["exported", "restarted"]:
        report = json.loads((root / ".kuzushi/reports/findings.json").read_text())
        assert report["count"] == 1 and report["findings"][0]["reviewDecision"] == "deferred"
    (evidence / "partial-replay.txt").write_text("replay " + folder.name)
    save(evidence, stage + "-check", {"status": "partial", "observationCount": 1,
        "decisions": decisions, "liveProviderRequests": 0, "targetSourceExecuted": False,
        "sourceUnchanged": True, "uafScannerExecuted": False})


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
    if stage == "prepare":
        prepare(root, evidence, Path(sys.argv[4]).resolve())
    else:
        wait(root, evidence, stage)
