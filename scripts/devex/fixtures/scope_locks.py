"""Real cross-process scope locks, cancellation and deterministic recovery."""
import fcntl
import json
import os
import signal
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

LOCKS = {"inventory": ".scope-inventory.lock", "strategy": ".strategy-ledger.lock"}


def seed(root):
    assert root.name == "fixture-target"
    for name in ("app.py", "config.env"):
        (root / name).unlink(missing_ok=True)
    (root / "README.md").write_text("Labeled scope cancellation fixture.\n")
    leaf = root / "deep"
    leaf.mkdir()
    for _ in range(300):
        leaf /= "a"
        leaf.mkdir()
    (leaf / "leaf.rs").write_text("pub fn leaf() {}\n")
    wide = root / "wide"
    wide.mkdir()
    for index in range(128):
        (wide / f"empty-{index}").mkdir()
    (root / ".kuzushi/v3").mkdir(parents=True, exist_ok=True)


def hold(root, evidence, role):
    lock = root / ".kuzushi/v3" / LOCKS[role]
    with lock.open("a+") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        (evidence / f"{role}-held.json").write_text(json.dumps({"pid": os.getpid(), "path": str(lock)}))
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            time.sleep(0.1)


def start(root, evidence, role):
    marker = evidence / f"{role}-held.json"
    marker.unlink(missing_ok=True)
    with (evidence / f"{role}-holder.log").open("w") as output:
        process = subprocess.Popen([sys.executable, "-B", __file__, str(root), str(evidence), "hold", role], stdout=output, stderr=subprocess.STDOUT)
    deadline = time.monotonic() + 5
    while not marker.is_file() and time.monotonic() < deadline:
        assert process.poll() is None, "Lock holder exited before acquiring the lock"
        time.sleep(0.05)
    assert marker.is_file(), "Lock holder did not acquire the exact file"
    os.kill(json.loads(marker.read_text())["pid"], 0)


def release(evidence, role):
    pid = json.loads((evidence / f"{role}-held.json").read_text())["pid"]
    os.kill(pid, signal.SIGTERM)


def scope_runs(root):
    rows = []
    for path in (root / ".kuzushi/v3/runs").glob("*/run.json"):
        summary = json.loads(path.read_text())
        assert summary["tool"] == "pack:scopes", "Unexpected tool ran"
        rows.append((path.parent, summary, json.loads(path.with_name("input.json").read_text())))
    return rows


def verify(root, evidence, stage):
    role = "inventory" if stage.startswith("inventory") else "strategy"
    operation = "create" if role == "inventory" else "latest"
    status = "running" if stage.endswith("waiting") else "canceled"
    deadline = time.monotonic() + 15
    matches = []
    while time.monotonic() < deadline:
        matches = [row for row in scope_runs(root) if row[1]["status"] == status and row[2].get("operation") == operation]
        if matches:
            break
        time.sleep(0.1)
    assert matches, f"No {status} {operation} run"
    os.kill(json.loads((evidence / f"{role}-held.json").read_text())["pid"], 0)
    queue = root / ".kuzushi/v3/strategy-queue.jsonl"
    if role == "inventory":
        assert not queue.exists() or not queue.read_text().strip(), "Canceled inventory published a proposal"
    else:
        assert len(queue.read_text().splitlines()) == 1, "Refresh mutated the proposal queue"
    assert not list((root / ".kuzushi/v3/campaigns").glob("*/plan.json"))
    db = root / ".kuzushi/v3/index.sqlite3"
    if db.is_file():
        with sqlite3.connect(db.as_uri() + "?mode=ro", uri=True) as connection:
            tables = {row[0] for row in connection.execute("select name from sqlite_master where type='table'")}
            for table in ("investigation_work_attempts", "investigation_call_reservations"):
                if table in tables:
                    assert connection.execute(f"select count(*) from {table}").fetchone()[0] == 0
    (evidence / f"{stage}-receipt.json").write_text(json.dumps({
        "operation": operation, "status": status, "runId": matches[-1][0].name,
        "holderVerifiedLive": True, "providerCalls": 0, "scanJobs": 0,
    }, indent=2) + "\n")


def recovered(root, evidence):
    queue = [json.loads(line) for line in (root / ".kuzushi/v3/strategy-queue.jsonl").read_text().splitlines()]
    assert len(queue) == 1
    reference = queue[0]["scopeProposalRef"]
    assert reference["revision"] == 1
    record = json.loads((root / ".kuzushi/v3/scan-scopes/revisions" / (reference["recordHash"] + ".json")).read_text())
    assert len(record["draft"]["scopes"]) == 1 and record["draft"]["scopes"][0]["paths"] == ["."]
    assert record["acceptance"] is None
    assert queue[0].get("tool") is None and queue[0].get("nextInput") is None
    (evidence / "recovered-receipt.json").write_text(json.dumps({"reference": reference, "source": record["source"], "forcedDivision": False, "scanJobs": 0, "providerCalls": 0}, indent=2) + "\n")


if __name__ == "__main__":
    root, evidence, action = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if action == "seed": seed(root)
    elif action == "hold": hold(root, evidence, sys.argv[4])
    elif action == "start": start(root, evidence, sys.argv[4])
    elif action == "release": release(evidence, sys.argv[4])
    elif action == "recovered": recovered(root, evidence)
    else: verify(root, evidence, action)
