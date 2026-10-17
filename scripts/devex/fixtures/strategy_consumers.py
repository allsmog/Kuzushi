"""Strategy refusal and exact local geometry, without provider work."""
import json
import sqlite3
import sys
import time
from pathlib import Path

from cargo_audit import hashes, save
from secret_settings import ledger


def seed(root, evidence, home):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "owned.c").write_text("// Owned selected metadata. Never executed.\n")
    (root / "other.c").write_text("// Owned unselected metadata. Never executed.\n")
    (root / "scope.txt").write_text("owned.c\n")
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text("")
    (evidence / "home.txt").write_text(str(home))
    save(evidence, "source-before", hashes(root))


def inspect(root, evidence, stage):
    assert hashes(root) == json.loads((evidence / "source-before.json").read_text())
    runs = [(path.parent, json.loads(path.read_text()))
            for path in (root / ".kuzushi/v3/runs").glob("*/run.json")]
    blocked = [(folder, run) for folder, run in runs if run["tool"] == "agentic-sast:scan"]
    expected = {"include": 1, "turns": 2, "stored": 3, "exclude": 4,
                "cleared": 4, "planned": 4, "exported": 4, "restarted": 4}[stage]
    assert len(blocked) == expected
    messages = {}
    for folder, run in blocked:
        assert run["status"] == "blocked"
        value = json.loads((folder / "result.json").read_text())
        assert value["status"] == "blocked" and "requires strategy=standard" in value["output"]
        assert "No model request started." in value["output"]
        messages[folder.name] = value["output"]
    for index, field in enumerate(["includePatterns", "maxModelTurns", "maxInventoryFiles", "excludePatterns"]):
        if expected > index:
            assert any("option " + field + " requires" in message for message in messages.values())
    if stage in ["stored", "exclude", "cleared", "planned", "exported", "restarted"]:
        refusal = next(run for run, message in messages.items() if "option maxInventoryFiles" in message)
        (evidence / "refusal-replay.txt").write_text("replay " + refusal)
    home = Path((evidence / "home.txt").read_text())
    settings = json.loads((home / ".kuzushi/v3/options.json").read_text())["bindings"]
    stored = settings.get("global/tool/agentic-sast:scan", {})
    if stage == "stored":
        assert stored["maxInventoryFiles"] == 80
    if stage in ["cleared", "planned", "exported", "restarted"]:
        assert "maxInventoryFiles" not in stored and "strategy" not in stored
    planning = [(folder, run) for folder, run in runs if run["tool"] == "full-mode:hunt"]
    complete = stage in ["planned", "exported", "restarted"]
    assert len(planning) == int(complete) and len(runs) == expected + int(complete)
    if complete:
        folder, run = planning[0]
        value = json.loads((folder / "result.json").read_text())
        assert run["status"] == value["status"] == "completed"
        data = value["data"]
        assert data["dryRun"] and not data["scanExecuted"] and data["chunksDispatched"] == 0
        assert not data["reuseCachedChunks"] and not data["strictDollarCeiling"]
        assert {item["path"] for chunk in data["plan"]["chunks"] for item in chunk["files"]} == {"owned.c"}
        (evidence / "plan-replay.txt").write_text("replay " + folder.name)
    assert not list((root / ".kuzushi/v3/campaigns").glob("**/queue.json"))
    with ledger(root, evidence) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        for table in ["finding_observations", "review_decisions", "investigation_call_reservations", "investigation_work_attempts"]:
            assert table not in tables or db.execute("select count(*) from " + table).fetchone()[0] == 0
    if stage in ["exported", "restarted"]:
        report = json.loads((root / ".kuzushi/reports/findings.json").read_text())
        assert report["count"] == 0 and report["findings"] == []
    save(evidence, stage + "-check", {"blockedRequests": expected, "localPlanningRuns": int(complete),
        "scanJobs": 0, "providerRequests": 0, "targetSourceExecuted": False, "sourceUnchanged": True})


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
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    else:
        wait(root, evidence, stage)
