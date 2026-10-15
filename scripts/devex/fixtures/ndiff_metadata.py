"""Owned advisory metadata. No network, model, patch or source execution."""
import hashlib
import json
import sqlite3
import sys
import time
from pathlib import Path

TOOL = "ndiff:fetch-cve"


def record(identifier):
    return {"id":identifier,"description":"Labeled owned metadata. No defect is claimed.",
            "cwes":[],"affected":[],"patches":[],"source":"claimed-source","raw":{}}


def prepare(root, evidence):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    source = root / "README.md"
    source.write_text("Owned metadata only. No source program or external service.\n")
    (evidence / "source.sha256").write_text(hashlib.sha256(source.read_bytes()).hexdigest())
    for label, value in [("valid",record("OWNED-ADVISORY")),("mismatch",record("OWNED-OTHER"))]:
        options = {"id":"OWNED-ADVISORY","offline":True,"record":value}
        (evidence / (label + "-command.txt")).write_text("run " + TOOL + " " + json.dumps(options))


def terminal_runs(root, count):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        rows = [(p.parent,json.loads(p.read_text())) for p in (root / ".kuzushi/v3/runs").glob("*/run.json")]
        matches = [(p,r) for p,r in rows if r.get("tool")==TOOL]
        if len(matches)==count and all(r["status"]!="running" for _,r in matches):
            return matches
        time.sleep(0.05)
    raise AssertionError("Expected terminal advisory receipts were not observed")


def verify(root, evidence, stage):
    assert hashlib.sha256((root / "README.md").read_bytes()).hexdigest()==(evidence / "source.sha256").read_text()
    runs = terminal_runs(root, 0 if stage=="before" else 1 if stage=="valid" else 2)
    if runs:
        completed = [(p,r) for p,r in runs if r["status"]=="completed"]
        assert len(completed)==1
        path,run = completed[0]
        result = json.loads((path / "result.json").read_text())
        assert result["data"]["record"]==record("OWNED-ADVISORY")
        assert result["data"]["retrieval"]["mode"]=="supplied-record"
        assert result["data"]["retrieval"]["sourceVerified"] is False
        assert not run.get("model") and not run.get("phase")
        digest = hashlib.sha256((path / "result.json").read_bytes()).hexdigest()
        if stage=="valid":
            (evidence / "valid.sha256").write_text(digest)
            (evidence / "replay-command.txt").write_text("replay " + run["runId"])
        else:
            assert digest==(evidence / "valid.sha256").read_text()
            failed = [(p,r) for p,r in runs if r["status"]=="failed"]
            assert len(failed)==1
            failure = json.loads((failed[0][0] / "result.json").read_text())
            assert "does not match requested" in failure["output"]
    counts = no_analysis_work(root)
    (evidence / (stage + "-check.json")).write_text(json.dumps({"toolRuns":len(runs),
        "sourceUnchanged":True,"providerRequests":0,"networkRequests":0,
        "sourceExecution":False,"phaseAttempts":0,"accountingTables":counts},indent=2) + "\n")


def no_analysis_work(root):
    names = ["finding_observations","review_decisions","investigation_call_reservations","investigation_work_attempts"]
    counts = dict.fromkeys(names)
    path = root / ".kuzushi/v3/index.sqlite3"
    if path.exists():
        # SQLite may need WAL sidecars even for reads. SQL writes stay forbidden.
        with sqlite3.connect(path.as_uri()+"?mode=rw",uri=True) as db:
            db.execute("PRAGMA query_only=ON")
            tables = {r[0] for r in db.execute("select name from sqlite_master where type='table'")}
            for table in names:
                count = db.execute("select count(*) from " + table).fetchone()[0] if table in tables else None
                assert count in [0,None]
                counts[table] = count
    for path in (root / ".kuzushi/v3/runs").glob("*/items.jsonl"):
        for line in path.read_text().splitlines():
            assert not json.loads(line)["item"]["type"].startswith("model_call")
    for path in (root / ".kuzushi").glob("**/phase-attempts*.jsonl"):
        assert not path.read_text().strip()
    return counts


def readable_narrow(evidence):
    pages = [p.read_text() for p in sorted(evidence.glob("*metadata-page-*-40x12.txt"))]
    assert len(pages)==3
    assert any("Labeled owned metadata." in page for page in pages)
    (evidence / "readability-check.json").write_text(json.dumps({"narrowPages":3,
        "metadataContentReachable":True},indent=2) + "\n")


if __name__=="__main__":
    root,evidence,stage = Path(sys.argv[1]).resolve(),Path(sys.argv[2]).resolve(),sys.argv[3]
    if stage=="prepare":prepare(root,evidence)
    elif stage=="readability":readable_narrow(evidence)
    else:verify(root,evidence,stage)
