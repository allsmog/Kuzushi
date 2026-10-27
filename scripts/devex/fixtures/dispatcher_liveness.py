"""Owned study and independent local work. Intercepted transport, no live inference."""
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

from investigation_journey import seed as source_seed
from rejected_context import execute

CAMPAIGN = "held-liveness-context"
INVESTIGATION = "held-liveness-accounting"
SOURCE_NAMES = ["main.rs", "app.py", "config.env", "package.json"]


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def source_hashes(root):
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in SOURCE_NAMES}


def prepare(root, evidence, runtime_home):
    source_seed(root, evidence, runtime_home)
    repo = Path(__file__).resolve().parents[3]
    shutil.copyfile(repo / "scripts/devex/fixtures/dispatcher_hold_provider.mjs", evidence / "provider.mjs")
    (root / "package.json").write_text(json.dumps({"name": "owned-liveness", "private": True,
        "dependencies": {"owned-package": "^1.0.0"},
        "scripts": {"postinstall": "touch must-not-execute"}}) + "\n")
    draft = execute(root, runtime_home, evidence, "context-plan", "campaign:context-study", {
        "campaignId": CAMPAIGN, "investigationId": INVESTIGATION,
        "contextInput": {"maxSourceBytes": 12000, "maxElements": 8,
                         "maxThreats": 6, "maxOutputTokens": 1024}})
    execute(root, runtime_home, evidence, "context-approval", "campaign:approve-allowance", {
        "investigationId": INVESTIGATION, "expectedRevision": 0,
        "model": "openai-codex:gpt-5.5", "maxProviderCalls": 2, "protectedReviewCalls": 1,
        "reason": "One owned intercepted hold, no live inference; one protected review call.",
        "campaignId": CAMPAIGN, "campaignPlanSha256": draft["planSha256"],
        "campaignJobs": 1, "maxJobAttempts": 1})
    assert len(plan(root)["jobs"]) == 1
    assert not (evidence / "held-calls.jsonl").exists()
    save(evidence, "source-before", source_hashes(root))
    (evidence / "external-observation.jsonl").write_text(json.dumps({"file": "main.rs", "line": 1,
        "title": "Owned external observation", "severity": "info", "class": "owned-refresh",
        "message": "Labeled fixture. No security defect is asserted."}) + "\n")


def plan(root):
    return json.loads((root / ".kuzushi/v3/campaigns" / CAMPAIGN / "plan.json").read_text())


def jobs(root):
    return json.loads((root / ".kuzushi/v3/campaigns" / CAMPAIGN / "queue.json").read_text())["jobs"]


def calls(evidence):
    return [json.loads(line) for line in (evidence / "held-calls.jsonl").read_text().splitlines()]


def accounting(root):
    db_path = root / ".kuzushi/v3/index.sqlite3"
    with sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True) as db:
        reservations = db.execute("select count(*),sum(settled_at is null) from investigation_call_reservations").fetchone()
        observations = db.execute("select count(*) from finding_observations").fetchone()[0]
    return {"reservations": list(reservations), "observations": observations}


def process_live(pid, *tokens):
    command = subprocess.check_output(["ps", "-p", str(pid), "-o", "command="], text=True)
    assert all(str(token) in command for token in tokens), "Unexpected owned fixture process"


def admitted(root, evidence):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if (evidence / "held-request.json").exists() and (root / ".kuzushi/v3/campaigns" / CAMPAIGN / "queue.json").exists():
            current = jobs(root)
            if len(current) == 1 and next(iter(current.values()))["state"] == "running":
                break
        time.sleep(0.1)
    else:
        raise AssertionError("Inspect the same recorded dispatcher; do not relaunch after an observation timeout")
    control = json.loads((root / ".kuzushi/v3/campaigns" / CAMPAIGN / "dispatcher-control.json").read_text())
    process_live(control["pid"], os.environ["KUZUSHI_NATIVE_BIN"], CAMPAIGN)
    process_live(calls(evidence)[0]["bridgePid"], evidence / "provider.mjs")
    assert len(calls(evidence)) == 1
    assert accounting(root) == {"reservations": [1, 1], "observations": 0}
    save(evidence, "admitted", {"control": control, "jobs": current,
         "planSha256": hashlib.sha256(json.dumps(plan(root), sort_keys=True).encode()).hexdigest(),
         "accounting": accounting(root), "liveProviderRequests": 0})


def inspect(root, evidence, stage):
    before = json.loads((evidence / "admitted.json").read_text())
    assert hashlib.sha256(json.dumps(plan(root), sort_keys=True).encode()).hexdigest() == before["planSha256"]
    assert source_hashes(root) == json.loads((evidence / "source-before.json").read_text())
    assert len(calls(evidence)) == 1 and not (root / "must-not-execute").exists()
    current = jobs(root)
    assert set(current) == set(before["jobs"]) and len(current) == 1
    if stage != "stopped":
        process_live(before["control"]["pid"], os.environ["KUZUSHI_NATIVE_BIN"], CAMPAIGN)
        assert next(iter(current.values()))["state"] == "running"
        assert not (root / ".kuzushi/v3/campaigns" / CAMPAIGN / "dispatcher-stop.json").exists()
    successes = []
    for path in (root / ".kuzushi/v3/runs").glob("*/result.json"):
        row = json.loads(path.read_text())
        if row.get("status") == "completed" and "componentCount" in row.get("data", {}):
            successes.append(path.parent.name)
            assert row["data"]["componentCount"] == 1
    assert len(successes) == 1, successes
    expected_observations = 1 if stage in ["imported", "stopped"] else 0
    assert accounting(root) == {"reservations": [1, 1], "observations": expected_observations}
    save(evidence, stage, {"jobs": current, "localSbomRuns": successes,
         "accounting": accounting(root), "sourceUnchanged": True,
         "interceptedRequests": 1, "liveProviderRequests": 0, "targetExecution": False})


def import_external(root, evidence, runtime_home):
    inspect(root, evidence, "local-completed")
    time.sleep(2.2)
    execute(root, runtime_home, evidence, "external-import", "workspace:import-findings", {
        "path": str(evidence / "external-observation.jsonl"), "tool": "owned-liveness-fixture"})
    inspect(root, evidence, "imported")


def stopped(root, evidence):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        current = jobs(root)
        job = next(iter(current.values()))
        if job["state"] == "parked" and job.get("reason") == "canceled":
            break
        time.sleep(0.1)
    else:
        raise AssertionError("Observe the original owned study and its bridge before any further action")
    assert job["attempts"] == 1 and len(job["attemptRuns"]) == 1
    before = json.loads((evidence / "admitted.json").read_text())
    stop = json.loads((root / ".kuzushi/v3/campaigns" / CAMPAIGN / "dispatcher-stop.json").read_text())
    assert stop == before["control"]
    wait_reaped(evidence, before["control"]["pid"], deadline)
    inspect(root, evidence, "stopped")


def wait_reaped(evidence, dispatcher_pid, deadline):
    bridge_pid = calls(evidence)[0]["bridgePid"]
    pending = {dispatcher_pid, bridge_pid}
    while pending and time.monotonic() < deadline:
        for pid in list(pending):
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                pending.remove(pid)
        if pending:
            time.sleep(0.1)
    assert not pending, "Inspect these same owned processes before continuing: " + str(pending)
    save(evidence, "reaped", {"dispatcherPid": dispatcher_pid, "bridgePid": bridge_pid,
                              "bothAbsent": True, "newProcessesStarted": False})


if __name__ == "__main__":
    root, evidence, runtime_home = [Path(value).resolve() for value in sys.argv[1:4]]
    stage = sys.argv[4]
    if stage == "prepare":
        prepare(root, evidence, runtime_home)
    elif stage == "admitted":
        admitted(root, evidence)
    elif stage == "import":
        import_external(root, evidence, runtime_home)
    elif stage == "stopped":
        stopped(root, evidence)
    else:
        inspect(root, evidence, stage)
