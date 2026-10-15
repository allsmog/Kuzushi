"""Inert advisory context, intercepted discovery and preserved human decisions."""
import hashlib
import json
import os
import shutil
import sqlite3
import sys
import time
from pathlib import Path
from variant_draft import seed as draft_seed
from rejected_context import execute

TOOL = "ndiff:hunt-variants"


def decision_digest(root):
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=rw", uri=True) as db:
        db.execute("PRAGMA query_only=ON")
        rows = db.execute("select * from review_decisions order by rowid").fetchall()
    return hashlib.sha256(json.dumps(rows, default=str).encode()).hexdigest()


def seed(root, evidence, home):
    draft_seed(root, evidence, home)
    shutil.copyfile(Path(__file__).with_name("advisory_observations_provider.mjs"), evidence / "provider.mjs")
    (evidence / "decision-before.sha256").write_text(decision_digest(root))
    (evidence / "command.txt").write_text("run " + TOOL + " " + json.dumps({
        "advisoryId": "OWNED-GREETING", "includeVendored": False,
        "maxFindings": 1, "maxOutputTokens": 4096, "maxModelTurns": 2,
        "pattern": {"fixShape": "Owned changed greeting marker", "vulnerableShape": "Owned prior greeting marker",
            "description": "Labeled inert context. No defect is claimed."},
        "allowanceRef": {"schemaVersion": 1, "investigationId": "owned-pattern", "revision": 1, "workId": "advisory-1"}}))


def verify(root, evidence, stage):
    assert decision_digest(root) == (evidence / "decision-before.sha256").read_text()
    assert hashlib.sha256((root / "hello.txt").read_bytes()).hexdigest() == (evidence / "source-before.sha256").read_text()
    active = json.loads((evidence / "active-before.json").read_text())
    assert hashlib.sha256(Path(active["path"]).read_bytes()).hexdigest() == active["sha256"]
    calls = evidence / "advisory-calls.jsonl"
    if stage == "before":
        assert not calls.exists()
        return
    deadline = time.monotonic() + 20
    records = []
    while time.monotonic() < deadline:
        records = [(p.parent, json.loads(p.read_text())) for p in (root / ".kuzushi/v3/runs").glob("*/run.json")]
        records = [(p, r) for p, r in records if r.get("tool") == TOOL]
        if len(records) == 1 and records[0][1]["status"] != "running":
            break
        time.sleep(.05)
    assert len(records) == 1 and records[0][1]["status"] == "partial", records
    path, run = records[0]
    data = json.loads((path / "result.json").read_text())["data"]
    assert data["coverage"]["complete"] is False and data["observationsVerified"] is False
    assert data["patternAccepted"] is False and data["candidateLocationsVerified"] is False
    assert data["findings"] == [] and len(data["treeHash"]) == 64
    assert not run.get("phase") and len(calls.read_text().splitlines()) == 1
    account = execute(root, Path(os.environ["HOME"]), evidence, "allowance-" + stage,
        "campaign:allowance", {"investigationId": "owned-pattern"})["allowance"]
    assert account["committedCalls"] == 1 and account["reviewCalls"] == 0
    assert account["limits"]["protectedReviewCalls"] == 1
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=rw", uri=True) as db:
        db.execute("PRAGMA query_only=ON")
        assert db.execute("select count(*) from finding_observations").fetchone()[0] == 1
        assert db.execute("select count(*) from review_decisions").fetchone()[0] == 1
    digest = hashlib.sha256((path / "result.json").read_bytes()).hexdigest()
    if stage == "result":
        (evidence / "result.sha256").write_text(digest)
        (evidence / "replay.txt").write_text("replay " + run["runId"])
    else:
        assert digest == (evidence / "result.sha256").read_text()
    (evidence / (stage + "-check.json")).write_text(json.dumps({"interceptedRequests": 1,
        "liveRequests": 0, "sourceExecution": False, "sourceUnchanged": True,
        "activeContextUnchanged": True, "humanDecisions": 1, "observations": 1,
        "committedCalls": 1, "protectedReviewCalls": 1, "phaseContinuation": False}, indent=2) + "\n")


if __name__ == "__main__":
    stage, root, evidence, *home = sys.argv[1:]
    root, evidence = Path(root).resolve(), Path(evidence).resolve()
    if stage == "seed":
        seed(root, evidence, Path(home[0]).resolve())
    else:
        verify(root, evidence, stage)
