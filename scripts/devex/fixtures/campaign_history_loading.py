"""Labeled unapproved metadata for keyboard interaction during bounded reads."""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_plan(base, identity, jobs):
    path = base / identity / "plan.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"campaignId": identity, "tool": "sast:scan",
        "kind": "scan-batch", "requestedWorkers": 1, "effectiveWorkers": 1,
        "jobs": jobs}, separators=(",", ":")) + "\n")


def seed(root, evidence, base):
    (root / "source.txt").write_text("Owned inert history fixture. Never executed.\n")
    write_plan(base, "held", [{"jobId": "held-1", "tool": "sast:scan", "input": {}},
                               {"jobId": "held-2", "tool": "sast:scan", "input": {}}])
    focus = "Labeled synthetic unapproved history, not a discovery result. " * 30
    for index in range(20):
        jobs = [{"jobId": "unstarted-" + str(job), "tool": "sast:scan",
                 "input": {"taskMode": "manual", "tasks": ["secret-scan"], "focus": focus}}
                for job in range(1000)]
        write_plan(base, "bulk-" + str(index).zfill(2), jobs)
    plans = {path.relative_to(base).as_posix(): digest(path) for path in base.glob("*/plan.json")}
    save(evidence / "loading-history-before.json", {"plans": plans,
         "sourceSha256": digest(root / "source.txt"),
         "metadataBytes": sum(path.stat().st_size for path in base.glob("*/plan.json")),
         "fixture": "21 synthetic unapproved plans; 20002 unstarted jobs; metadata reading only"})
    command = [os.environ["KUZUSHI_NATIVE_BIN"], "run", "campaign:status", "--target", str(root)]
    started = time.monotonic()
    result = subprocess.run(command, capture_output=True, text=True, timeout=60)
    (evidence / "loading-headless-history.json").write_text(result.stdout)
    (evidence / "loading-headless-history.stderr.txt").write_text(result.stderr)
    assert result.returncode == 4, result.stderr
    output = json.loads(result.stdout)
    assert output["status"] == "partial"
    assert output["data"]["historyCoverage"]["byteLimitReached"]
    save(evidence / "loading-headless-check.json", {"elapsedSeconds": time.monotonic() - started,
         "historyCoverage": output["data"]["historyCoverage"], "providerRequests": 0})


def verify(root, evidence, base):
    before = json.loads((evidence / "loading-history-before.json").read_text())
    assert digest(root / "source.txt") == before["sourceSha256"]
    assert {path.relative_to(base).as_posix(): digest(path) for path in base.glob("*/plan.json")} == before["plans"]
    assert not list(base.glob("*/queue.json")), "History browsing created a queue"
    counts = {}
    database = root / ".kuzushi/v3/index.sqlite3"
    if database.exists():
        with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
            tables = {row[0] for row in connection.execute("select name from sqlite_master where type='table'")}
            for table in ["investigation_work_attempts", "investigation_call_reservations",
                          "finding_observations", "review_decisions"]:
                if table in tables:
                    counts[table] = connection.execute("select count(*) from " + table).fetchone()[0]
    assert all(value == 0 for value in counts.values()), counts
    captures = list(evidence.glob("*.txt"))
    loading = [path.name for path in captures if "Loading history." in path.read_text()]
    save(evidence / "loading-history-inspection-check.json", {"sourceAndPlansUnchanged": True,
         "queueCreated": False, "counts": counts, "providerRequests": 0, "sourceExecuted": False,
         "capturedLoadingStates": loading,
         "qualification": "Local metadata stress and keyboard recovery; controlled Rust reader tests separately hold requests in flight."})


def verify_title(evidence):
    capture = next(evidence.glob("*-input-after-history-request.txt"))
    text = capture.read_text()
    if "Loading history." in text:
        assert "Investigation history" in text, text
    else:
        assert "Study jobs" in text, text
    assert "view:campaign" not in text, text
    save(evidence / "loading-history-title-check.json", {"capture": capture.name,
         "loadingCaptured": "Loading history." in text, "operatorTitleMatchesReadState": True})


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    assert root == evidence / "fixture-target"
    base = root / ".kuzushi/v3/campaigns"
    if sys.argv[3] == "seed":
        seed(root, evidence, base)
    elif sys.argv[3] == "title":
        verify_title(evidence)
    else:
        verify(root, evidence, base)
