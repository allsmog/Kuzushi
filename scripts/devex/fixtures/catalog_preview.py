"""Owned catalog planning only. No source execution, engine or provider."""
import hashlib
import json
import sqlite3
import sys
import time
from pathlib import Path

TOOL = "threat-intel:apply"
CATALOG = '''schema_version = "1"
[[entry]]
id = "owned-record"
title = "Labeled metadata only"
cwe = "CWE-20"
severity = "low"
hunt = "taint-iris-next"
[entry.taint_iris_next]
taint_class = "owned-metadata"
languages = ["text"]
source_signals = ["OwnedInput"]
sink_signals = ["OwnedRecord"]
[[entry]]
id = "owned-unsupported"
cwe = "CWE-20"
severity = "low"
hunt = "owned-inert"
'''


def prepare(root, evidence):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    source = root / "README.md"
    source.write_text("Labeled owned catalog metadata. No executable source.\n")
    (evidence / "source.sha256").write_text(hashlib.sha256(source.read_bytes()).hexdigest())
    catalog_path(root).parent.mkdir(parents=True, exist_ok=True)
    catalog_path(root).write_text(CATALOG)
    (evidence / "preview-command.txt").write_text("run " + TOOL)


def catalog_path(root):
    return root / ".kuzushi/catalogs/owned.toml"


def terminal_runs(root, count):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        rows = [(p.parent, json.loads(p.read_text())) for p in (root / ".kuzushi/v3/runs").glob("*/run.json")]
        rows = [(p, r) for p, r in rows if r.get("tool") == TOOL]
        if len(rows) == count and all(r["status"] != "running" for _, r in rows):
            return rows
        time.sleep(0.05)
    raise AssertionError("Expected terminal preview receipts were not observed")


def verify(root, evidence, stage):
    assert hashlib.sha256((root / "README.md").read_bytes()).hexdigest() == (evidence / "source.sha256").read_text()
    runs = terminal_runs(root, 1 if stage == "planned" else 2)
    completed = [(p, r) for p, r in runs if r["status"] == "completed"]
    assert len(completed) == 1
    path, run = completed[0]
    result = json.loads((path / "result.json").read_text())
    assert result["data"]["summary"]["dryRun"] is True
    assert result["data"]["summary"]["totalEntries"] == 2
    assert result["data"]["summary"]["planned"] == 1
    assert result["data"]["summary"]["dispatchRequests"] == 0
    assert "no hunts started" in result["output"]
    assert [r["status"] for r in result["data"]["entries"]] == ["planned", "skipped"]
    assert not run.get("model")
    digest = hashlib.sha256((path / "result.json").read_bytes()).hexdigest()
    if stage == "planned":
        (evidence / "result.sha256").write_text(digest)
        (evidence / "replay-command.txt").write_text("replay " + run["runId"])
    else:
        assert digest == (evidence / "result.sha256").read_text()
        assert len([r for _, r in runs if r["status"] == "failed"]) == 1
    accounting = verify_no_work(root)
    (evidence / (stage + "-check.json")).write_text(json.dumps({
        "toolRuns":len(runs),"plannedEntries":1,"skippedEntries":1,"catalogPreviewRetained":True,
        "modelSelected":False,"providerRequests":0,"sourceExecuted":False,
        "sourceUnchanged":True,"accountingTables":accounting}, indent=2) + "\n")


def verify_no_work(root):
    counts = {}
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=rw", uri=True) as db:
        db.execute("PRAGMA query_only=ON")
        tables = {r[0] for r in db.execute("select name from sqlite_master where type='table'")}
        for table in ["finding_observations", "review_decisions", "investigation_call_reservations", "investigation_work_attempts"]:
            count = db.execute("select count(*) from " + table).fetchone()[0] if table in tables else None
            assert count in [0, None]
            counts[table] = count
    for path in (root / ".kuzushi/v3/runs").glob("*/items.jsonl"):
        for line in path.read_text().splitlines():
            assert not json.loads(line)["item"]["type"].startswith("model_call")
    for path in (root / ".kuzushi").glob("**/phase-attempts*.jsonl"):
        assert not path.read_text().strip(), "Catalog preview created phase progress"
    return counts


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "prepare":
        prepare(root, evidence)
    elif stage == "break-catalog":
        catalog_path(root).write_text("invalid = [")
    elif stage == "restore-catalog":
        catalog_path(root).write_text(CATALOG)
    else:
        verify(root, evidence, stage)
