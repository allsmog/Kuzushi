"""Owned metadata-only recommendation audit. No models or source execution."""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def native(root, evidence, name, inputs, succeeds=True, partial=False):
    result = subprocess.run([os.environ["KUZUSHI_NATIVE_BIN"], "--target", str(root),
        "run", "module-recommender:recommend", "--input", json.dumps(inputs)],
        text=True, capture_output=True, timeout=60)
    (evidence / (name + ".stdout.json")).write_text(result.stdout)
    (evidence / (name + ".stderr.txt")).write_text(result.stderr)
    if not succeeds:
        assert result.returncode != 0
        assert "approved allowanceRef" in result.stderr, result.stderr
        return None
    if partial:
        assert result.returncode != 0, "Partial work must keep the CLI's nonzero exit semantics."
    else:
        assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def assert_no_work(root):
    path = root / ".kuzushi/v3/index.sqlite3"
    if path.is_file():
        with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as db:
            tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
            for table in ["finding_observations", "review_decisions", "investigation_call_reservations", "investigation_work_attempts"]:
                if table in tables:
                    assert db.execute("select count(*) from " + table).fetchone()[0] == 0, table
    assert not (root / ".kuzushi/threat-model.json").exists()
    assert not (root / ".kuzushi/v3/campaigns").exists()


def verify_report(value, partial=False):
    assert value["status"] == ("partial" if partial else "completed"), value
    data = value["data"]
    assert data["rankingMode"] == "deterministic"
    assert data["model"] is None and data["costUsdExact"] is True
    assert data["providerSpendUnresolved"] is False
    assert data["inventoryCoverage"]["completeRepositoryCoverage"] is False
    assert data["findingsCoverage"]["completeLedgerCoverage"] is False
    assert data["recommendations"]
    assert all(not row["tool"].startswith(("verify:", "patch:", "offense:", "pwn:")) for row in data["recommendations"])
    if partial:
        assert data["inventoryCoverage"]["status"] == "partial"
        assert data["inventoryCoverage"]["truncatedFiles"] > 0


def prepare(root, evidence, home):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "Cargo.toml").write_text('[package]\nname="owned-metadata"\nversion="0.0.0"\nedition="2021"\n')
    (root / "owned.rs").write_text("// Owned inert metadata fixture. Never compiled or executed.\n")
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('model="openai-codex:gpt-5.5"\n[runtime]\nthinking_level="medium"\n')
    value = native(root, evidence, "default-recommendations", {})
    verify_report(value)
    native(root, evidence, "unapproved-ranking", {"useModelRanking": True}, False)
    save(evidence, "state", {"home":str(home),"configHash":hashlib.sha256(config.read_bytes()).hexdigest(),
        "sourceHash":hashlib.sha256((root / "owned.rs").read_bytes()).hexdigest()})
    verify(root, evidence, "prepared")


def partial(root, evidence):
    (root / "large.rs").write_text("// Owned prefix inspection fixture. Never executed.\n" * 10000)
    value = native(root, evidence, "partial-recommendations", {}, partial=True)
    verify_report(value, True)
    save(evidence, "before-refresh", {"runId":(root / ".kuzushi/v3/latest").read_text().strip()})
    verify(root, evidence, "partial")


def refreshed(root, evidence):
    prior = json.loads((evidence / "before-refresh.json").read_text())["runId"]
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        current = (root / ".kuzushi/v3/latest").read_text().strip()
        result = root / ".kuzushi/v3/runs" / current / "result.json"
        if current != prior and result.is_file():
            verify_report(json.loads(result.read_text()), True)
            save(evidence, "refresh-completed", {"priorRunId":prior,"runId":current,
                "newTerminalResult":True,"deterministic":True})
            return
        time.sleep(0.1)
    raise AssertionError("Explicit refresh did not publish a new terminal result.")


def verify(root, evidence, stage):
    state = json.loads((evidence / "state.json").read_text())
    config = Path(state["home"]) / ".kuzushi/v3/config.toml"
    assert hashlib.sha256(config.read_bytes()).hexdigest() == state["configHash"]
    assert hashlib.sha256((root / "owned.rs").read_bytes()).hexdigest() == state["sourceHash"]
    assert_no_work(root)
    queues = list((root / ".kuzushi").rglob("strategy-queue.jsonl"))
    assert queues
    proposals = [json.loads(line) for line in queues[0].read_text().splitlines() if line.strip()]
    assert proposals and all(row["status"] == "proposed" for row in proposals)
    if stage == "after":
        refreshed_id = json.loads((evidence / "refresh-completed.json").read_text())["runId"]
        captures = list(evidence.glob("*-refreshed-reader.txt"))
        assert captures and refreshed_id in captures[0].read_text(), "Reader retained the old report after refresh."
        result = json.loads((root / ".kuzushi/v3/runs" / refreshed_id / "result.json").read_text())
        tail = list(evidence.glob("*-reader-tail-40x12.txt"))
        text = " ".join(tail[0].read_text().split())
        assert result["data"]["recommendations"][-1]["reason"] in text, "Final rationale was not fully readable at 40x12."
    save(evidence, stage + "-check", {"providerRequests":0,"scannerJobs":0,"sourceExecuted":False,
        "findingObservations":0,"reviewDecisions":0,"providerReservations":0,
        "workAttempts":0,"configurationUnchanged":True,"ownedSourceUnchanged":True,
        "proposalsStillUnapproved":True,"syntheticRecommendationPayload":False})


root, evidence = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
action = sys.argv[3]
if action == "prepare":
    prepare(root, evidence, Path(sys.argv[4]).resolve())
elif action == "partial":
    partial(root, evidence)
elif action == "refreshed":
    refreshed(root, evidence)
else:
    verify(root, evidence, action)
