"""Owned synthetic stored-result fixture. No engine or source execution."""
import hashlib
import json
import sqlite3
import sys
from pathlib import Path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare(root, evidence):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    source = root / "source.txt"
    source.write_text("Owned inert source. Never executed.\n")
    (evidence / "source-before.sha256").write_text(digest(source))
    workspace = evidence / "stored-workspace"
    for name in ["workspace.json", "targets/c/owned/harness.cpp", "bin/owned/fuzzer"]:
        path = workspace / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("Synthetic stored marker. Never executed.\n")
    data = workspace / "data"
    data.mkdir()
    row = {"event": "recorded", "finding_id": "owned-synthetic-record", "verified": True,
           "target": "owned", "signature": "synthetic-stored-record",
           "crash_excerpt": "Synthetic metadata only. No crash or source execution."}
    (data / "findings-index.jsonl").write_text(json.dumps(row) + "\nmalformed owned row\n")
    options = {"workspaceRoot": str(workspace), "dataRoot": str(data)}
    (evidence / "status-command.txt").write_text("run fuzz:status " + json.dumps(options))
    (evidence / "import-command.txt").write_text("run fuzz:import " + json.dumps({"dataRoot": str(data)}))


def invalidate(evidence):
    path = evidence / "stored-workspace/data/findings-index.jsonl"
    path.rename(path.with_suffix(".saved"))
    path.mkdir()


def verify(root, evidence, stage):
    assert digest(root / "source.txt") == (evidence / "source-before.sha256").read_text()
    results = [(path, json.loads(path.read_text()))
               for path in (root / ".kuzushi/v3/runs").glob("*/result.json")]
    partial = [(path, value) for path, value in results if value.get("status") == "partial"]
    assert len(partial) == 2, [(str(path), value.get("status")) for path, value in results]
    for _, value in partial:
        assert value["data"]["verificationAuthority"] == "external-engine"
        assert value["data"]["localReproductionPerformed"] is False
    status = [(path, value) for path, value in partial if "inspectionLimits" in value["data"]]
    assert status[0][1]["data"]["findings"] == {"total": 1, "verified": 1, "malformedRows": 1}
    imported = [(path, value) for path, value in partial if "summary" in value["data"]]
    assert imported[0][1]["data"]["summary"]["imported"] == 1
    (evidence / "partial-replay.txt").write_text("replay " + status[0][0].parent.name)
    hashes = {path.parent.name: digest(path) for path, _ in partial}
    if stage == "imported":
        (evidence / "partial-before.json").write_text(json.dumps(hashes))
    else:
        assert hashes == json.loads((evidence / "partial-before.json").read_text())
        failed = [(path, value) for path, value in results if value.get("status") == "failed"]
        assert len(failed) == 1
        (evidence / "failed-replay.txt").write_text("replay " + failed[0][0].parent.name)
    for path in (root / ".kuzushi/v3/workflow").glob("phase-attempts*.jsonl"):
        assert not path.read_text().strip(), "Stored history cannot create a Scan attempt"
    verify_store(root)
    (evidence / f"{stage}-check.json").write_text(json.dumps({"partialReceipts": 2,
        "failedReceipts": 0 if stage == "imported" else 1, "providerCalls": 0,
        "sourceExecuted": False, "sourceBytesUnchanged": True, "scanAttempts": 0,
        "syntheticFindingCount": 1}, indent=2) + "\n")


def verify_store(root):
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=rw", uri=True) as db:
        db.execute("PRAGMA query_only=ON")
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        for table in ["investigation_call_reservations", "investigation_work_attempts", "review_decisions"]:
            if table in tables:
                assert db.execute("select count(*) from " + table).fetchone()[0] == 0, table
        assert db.execute("select count(*) from finding_observations").fetchone()[0] == 1


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    stage = sys.argv[3]
    if stage == "prepare":
        prepare(root, evidence)
    elif stage == "invalidate":
        invalidate(evidence)
    else:
        verify(root, evidence, stage)
