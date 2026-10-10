"""Finite owned ledger writes while Review reads; no scanner or model calls."""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

PREFIX = "app::findings::read_projection::tests::native_fixture::"


def command(name):
    return [os.environ["KUZUSHI_SNAPSHOT_TEST_BIN"], "--exact", PREFIX + name, "--ignored", "--nocapture"]


def environment(root):
    env = {key: value for key, value in os.environ.items() if key not in [
        "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "KUZUSHI_MODEL", "KUZUSHI_LANGGRAPH_BRIDGE", "NODE_OPTIONS"]}
    env["KUZUSHI_REVIEW_SNAPSHOT_FIXTURE_OUT"] = str(root)
    return env


def source_hash(root):
    return hashlib.sha256((root / "owned.rs").read_bytes()).hexdigest()


def prepare(root, evidence):
    result = subprocess.run(command("prepare_native_review_snapshot_fixture"), env=environment(root),
        capture_output=True, text=True, timeout=60, check=True)
    (evidence / "prepare.log").write_text(result.stdout + result.stderr)
    receipt = json.loads((root / "snapshot-fixture.json").read_text())
    assert receipt["findingsAreSynthetic"] and receipt["findingCount"] == 800
    assert receipt["selectedFingerprint"] != receipt["writerFingerprint"]
    (evidence / "open.txt").write_text("open " + receipt["selectedAlias"])
    (evidence / "source-before.sha256").write_text(source_hash(root))
    inspect(root, evidence, "prepared", 0)


def progress(root):
    return json.loads((root / "snapshot-writer-progress.json").read_text())


def live_process(evidence):
    receipt = json.loads((evidence / "writer-process.json").read_text())
    result = subprocess.run(["ps", "-p", str(receipt["pid"]), "-o", "lstart=", "-o", "command="],
        capture_output=True, text=True, check=False)
    assert result.returncode == 0, "Owned writer handle is no longer live"
    assert result.stdout.strip() == receipt["identity"], "Writer handle identity changed"
    return receipt


def start(root, evidence):
    log = (evidence / "writer.log").open("w")
    process = subprocess.Popen(command("run_native_review_snapshot_updates"), env=environment(root),
        stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    deadline = time.monotonic() + 15
    while not (root / "snapshot-writer-progress.json").exists():
        assert process.poll() is None, "Writer stopped before its first commit"
        assert time.monotonic() < deadline, "Writer did not commit within the finite start wait"
        time.sleep(0.1)
    identity = subprocess.run(["ps", "-p", str(process.pid), "-o", "lstart=", "-o", "command="],
        capture_output=True, text=True, check=True).stdout.strip()
    (evidence / "writer-process.json").write_text(json.dumps({"pid": process.pid, "identity": identity}) + "\n")
    log.close()
    inspect(root, evidence, "writing", 0)


def active(root, evidence, decisions):
    live_process(evidence)
    before = progress(root)
    deadline = time.monotonic() + 8
    while progress(root)["writes"] <= before["writes"]:
        live_process(evidence)
        assert time.monotonic() < deadline, "Live writer has not made a new commit"
        time.sleep(0.1)
    inspect(root, evidence, "active-" + str(decisions), decisions)


def stop(root, evidence):
    (root / "stop-snapshot-writer").write_text("Explicitly stop the owned writer.\n")
    deadline = time.monotonic() + 12
    while not (root / "snapshot-writer-finished").exists():
        live_process(evidence)
        assert time.monotonic() < deadline, "Owned writer did not stop in time"
        time.sleep(0.1)
    (evidence / "writer-final.json").write_text(json.dumps(progress(root), indent=2) + "\n")
    inspect(root, evidence, "stopped", 1)


def inspect(root, evidence, label, decisions):
    assert source_hash(root) == (evidence / "source-before.sha256").read_text()
    receipt = json.loads((root / "snapshot-fixture.json").read_text())
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
        observations = db.execute("select count(*) from finding_observations").fetchone()[0]
        reviews = db.execute("select finding_id, decision_verdict, rationale, author from review_decisions order by id").fetchall()
        assert len(reviews) == decisions, reviews
        if decisions:
            assert reviews[-1] == (receipt["selectedId"], "deferred", "J155 owned unchanged finding deferred during updates", "human")
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        for table in ["investigation_call_reservations", "investigation_work_attempts"]:
            if table in tables:
                assert db.execute("select count(*) from " + table).fetchone()[0] == 0
    (evidence / (label + "-check.json")).write_text(json.dumps({"findingsAreSynthetic": True,
        "initialObservations":800,"observations":observations,"humanDecisions":decisions,
        "providerRequests":0,"scannerJobs":0,"sourceExecuted":False,"sourceUnchanged":True}, indent=2) + "\n")


root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
if stage == "prepare":
    prepare(root, evidence)
elif stage == "start":
    start(root, evidence)
elif stage == "active":
    active(root, evidence, 0)
elif stage == "decided":
    active(root, evidence, 1)
elif stage == "stop":
    stop(root, evidence)
else:
    inspect(root, evidence, stage, 1)
