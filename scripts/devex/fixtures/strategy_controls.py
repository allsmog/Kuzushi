"""Standard discovery refuses unused chunk controls before model work."""
import hashlib
import json
import sqlite3
import sys
import time
from pathlib import Path

from cargo_audit import hashes, save
from secret_settings import ledger


def prepare(root, evidence, home):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "owned.c").write_text("// Owned inert source. Never executed.\n")
    (root / "scope.txt").write_text("owned.c\n")
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text("")
    (evidence / "home.txt").write_text(str(home))
    (evidence / "draft.txt").write_text("retained 資料 draft")
    save(evidence, "source-before", hashes(root))


def inspect(root, evidence, stage):
    assert hashes(root) == json.loads((evidence / "source-before.json").read_text())
    runs = [(p.parent, json.loads(p.read_text()))
            for p in (root / ".kuzushi/v3/runs").glob("*/run.json")]
    expected = {"dry-run": 1, "reading": 1, "stored": 2, "scope": 3, "budget": 4, "cleared": 4, "restarted": 4}[stage]
    assert len(runs) == expected
    reasons = []
    dry_runs = []
    for folder, run in runs:
        assert run["tool"] == "agentic-sast:scan" and run["status"] == "blocked"
        result = json.loads((folder / "result.json").read_text())
        assert result["status"] == "blocked"
        message = result["output"]
        assert "requires strategy=chunked" in message and "No model request started." in message
        reasons.append(message)
        if "option dryRun" in message:
            dry_runs.append(folder.name)
    assert len(dry_runs) == min(expected, 2)
    canonical = root / ".kuzushi/v3/runs" / sorted(dry_runs)[0]
    receipt_hashes = {name: hashlib.sha256((canonical / name).read_bytes()).hexdigest()
                      for name in ["run.json", "result.json", "items.jsonl"]}
    original = evidence / "original-receipt.json"
    if stage == "reading":
        save(evidence, "original-receipt", receipt_hashes)
    elif original.exists():
        assert receipt_hashes == json.loads(original.read_text()), "Reading changed the stored receipt"
    if expected >= 3:
        assert any("option scopeFile" in message for message in reasons)
    if expected == 4:
        assert any("option budgetUsd" in message for message in reasons)
    home = Path((evidence / "home.txt").read_text())
    settings = json.loads((home / ".kuzushi/v3/options.json").read_text())
    values = settings["bindings"].get("global/tool/agentic-sast:scan", {})
    if stage == "stored":
        assert values["dryRun"] is True
    if stage in ["cleared", "restarted"]:
        assert "dryRun" not in values and "strategy" not in values
        before = next(evidence.glob("*refusal-reading-40x12-2.txt")).read_text().splitlines()
        after = next(evidence.glob("*restored-summary-40x12.txt")).read_text().splitlines()
        assert before[:6] == after[:6], "Summary reading position changed after the receipt switch"
        draft = next(evidence.glob("*prompt-draft-retained.txt")).read_text()
        assert "retained 資料 draft" in draft and "REPLAY · Full receipt" not in draft
        receipt = next(evidence.glob("*-full-receipt-40x12.txt")).read_text().splitlines()
        heading = next(index for index, line in enumerate(receipt) if "REPLAY" in line)
        assert "Outcome ·" in receipt[heading + 1], "Receipt heading wrapped onto a border-only row"
    assert not list((root / ".kuzushi/v3/campaigns").glob("**/queue.json"))
    with ledger(root, evidence) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        for table in ["finding_observations", "review_decisions", "investigation_call_reservations", "investigation_work_attempts"]:
            assert table not in tables or db.execute("select count(*) from " + table).fetchone()[0] == 0
    (evidence / "dry-replay.txt").write_text("replay " + sorted(dry_runs)[0])
    save(evidence, stage + "-check", {"blockedRuns": expected, "scanJobs": 0,
        "liveProviderRequests": 0, "targetSourceExecuted": False, "sourceUnchanged": True})


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
