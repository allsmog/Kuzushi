"""Owned directory metadata and missing-prerequisite receipts. No engine or model."""
import hashlib
import json
import sqlite3
import sys
import time
from pathlib import Path

TOOLS = ["taint-iris-next:dataflow-plan", "taint-iris-next:source-sink-trace"]


def prepare(root, evidence):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    source = root / "README.md"
    source.write_text("Labeled owned directory metadata. No usable source or context.\n")
    (evidence / "source.sha256").write_text(hashlib.sha256(source.read_bytes()).hexdigest())
    deepest = root
    for _ in range(160):
        deepest = deepest / "n"
        deepest.mkdir()
    for label, tool in zip(["plan", "alias"], TOOLS):
        (evidence / (label + "-command.txt")).write_text("run " + tool + ' {"backend":"structural","discoverSignals":false}')


def records(root, count):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        rows = [(p.parent, json.loads(p.read_text())) for p in (root / ".kuzushi/v3/runs").glob("*/run.json")]
        matches = [(p, r) for p, r in rows if r.get("tool") in TOOLS]
        if len(matches) == count and all(r["status"] == "failed" for _, r in matches):
            return matches
        time.sleep(0.05)
    raise AssertionError("Expected missing-prerequisite receipts were not observed")


def verify(root, evidence, stage):
    assert hashlib.sha256((root / "README.md").read_bytes()).hexdigest() == (evidence / "source.sha256").read_text()
    runs = records(root, 0 if stage == "before" else 1 if stage == "plan" else 2)
    for path, run in runs:
        result = json.loads((path / "result.json").read_text())
        assert result["status"] == "failed" and result["data"]["status"] == "missing-context"
        assert not run.get("model") and not run.get("phase")
        digest = hashlib.sha256((path / "result.json").read_bytes()).hexdigest()
        if run["tool"] == TOOLS[0]:
            if stage == "plan":
                (evidence / "result.sha256").write_text(digest)
                (evidence / "replay-command.txt").write_text("replay " + run["runId"])
            else:
                assert digest == (evidence / "result.sha256").read_text()
    accounting = verify_no_work(root)
    (evidence / (stage + "-check.json")).write_text(json.dumps({"toolRuns":len(runs),
        "providerRequests":0,"sourceExecuted":False,"sourceUnchanged":True,
        "phaseAttempts":0,"accountingTables":accounting}, indent=2) + "\n")


def verify_no_work(root):
    names = ["finding_observations", "review_decisions", "investigation_call_reservations", "investigation_work_attempts"]
    counts = dict.fromkeys(names)
    path = root / ".kuzushi/v3/index.sqlite3"
    if path.exists():
        with sqlite3.connect(path.as_uri() + "?mode=rw", uri=True) as db:
            db.execute("PRAGMA query_only=ON")
            tables = {r[0] for r in db.execute("select name from sqlite_master where type='table'")}
            for table in names:
                count = db.execute("select count(*) from " + table).fetchone()[0] if table in tables else None
                assert count in [0, None]
                counts[table] = count
    for path in (root / ".kuzushi/v3/runs").glob("*/items.jsonl"):
        for line in path.read_text().splitlines():
            assert not json.loads(line)["item"]["type"].startswith("model_call")
    for path in (root / ".kuzushi").glob("**/phase-attempts*.jsonl"):
        assert not path.read_text().strip(), "Planning helper created phase progress"
    return counts


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "prepare":
        prepare(root, evidence)
    else:
        verify(root, evidence, stage)
