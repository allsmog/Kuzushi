"""Real fixed-plan Stop and retained accounting, with intercepted transport only."""
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import investigation_journey as investigation


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def scan_plan(root):
    return next(plan for plan in investigation.plans(root) if plan["kind"] == "scan-batch")


def queue(root, plan):
    return json.loads((root / ".kuzushi/v3/campaigns" / plan["campaignId"] / "queue.json").read_text())["jobs"]


def live(pid, *tokens):
    os.kill(pid, 0)
    command = subprocess.check_output(["ps", "-p", str(pid), "-o", "command="], text=True).replace("/private/tmp/", "/tmp/")
    assert all(str(token).replace("/private/tmp/", "/tmp/") in command for token in tokens), "Unexpected owned fixture process"


def admitted(root, evidence):
    plan = scan_plan(root)
    deadline = time.monotonic() + 30
    marker = evidence / "cancellation-admitted.json"
    while time.monotonic() < deadline:
        jobs = queue(root, plan)
        if marker.exists() and sum(job["state"] == "completed" for job in jobs.values()) == 1:
            break
        time.sleep(0.1)
    else:
        raise AssertionError("Observe the same approved dispatcher; do not relaunch after an observation timeout")
    receipt = json.loads(marker.read_text())
    control = json.loads((root / ".kuzushi/v3/campaigns" / plan["campaignId"] / "dispatcher-control.json").read_text())
    live(control["pid"], os.environ["KUZUSHI_NATIVE_BIN"], root, plan["campaignId"])
    live(receipt["bridgePid"], evidence / "provider.mjs")
    assert receipt["responseReturned"] is False and len(investigation.calls(evidence)) == 3
    assert sorted(job["state"] for job in jobs.values()) == ["completed", "planned", "running"]
    account = investigation.accounting(root, plan["investigationId"])
    assert account["reservations"] == [3, 1, 0], account
    save(evidence, "before-stop", {"planSha256": hashlib.sha256(json.dumps(plan, sort_keys=True).encode()).hexdigest(),
        "jobs": jobs, "control": control, "admittedRequest": receipt, "accounting": account})


def canceled(root, evidence):
    plan = scan_plan(root)
    jobs = investigation.wait_jobs(root, plan, {"completed", "parked"})
    before = json.loads((evidence / "before-stop.json").read_text())
    assert set(jobs) == set(before["jobs"])
    runs = [attempt for job in jobs.values() for attempt in job.get("attemptRuns", [])]
    save(evidence, "after-stop", {"jobs": jobs, "attemptRuns": runs, "accounting": investigation.accounting(root, plan["investigationId"])})
    assert sum(job["state"] == "completed" for job in jobs.values()) == 1
    stopped = [job for job in jobs.values() if job["state"] == "parked" and job.get("attemptRuns")]
    assert len(stopped) == 1 and stopped[0]["reason"] == "canceled", stopped
    assert stopped[0]["attemptRuns"][-1]["outcome"] == "canceled", stopped
    assert stopped[0]["dispatches"] == 1 and stopped[0]["providerSpendUnresolved"] is True
    unstarted = [job for job in jobs.values() if not job.get("attemptRuns")]
    assert len(unstarted) == 1 and unstarted[0]["dispatches"] == 0 and unstarted[0]["attempts"] == 0
    summary = json.loads((root / ".kuzushi/v3/runs" / stopped[0]["runId"] / "run.json").read_text())
    assert summary["status"] == "canceled", summary["status"]
    assert summary["kind"] == "run" and summary["tool"] == "sast:scan"
    bridge = before["admittedRequest"]["bridgePid"]
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        probe = subprocess.run(["ps", "-p", str(bridge), "-o", "command="], capture_output=True, text=True)
        if "provider.mjs" not in probe.stdout:
            break
        time.sleep(0.1)
    else:
        raise AssertionError("Canceled owned bridge must not outlive its job")
    save(evidence, "canceled-run", {"summary": summary, "bridgeReaped": True, "liveProviderRequests": 0})
    assert investigation.accounting(root, plan["investigationId"])["reservations"] == [3, 1, 0]
    assert len(investigation.calls(evidence)) == 3


def verify_history(root, evidence):
    plan = scan_plan(root)
    jobs = queue(root, plan)
    before = json.loads((evidence / "before-stop.json").read_text())
    assert hashlib.sha256(json.dumps(plan, sort_keys=True).encode()).hexdigest() == before["planSha256"]
    for job_id, original in before["jobs"].items():
        for attempt in original.get("attemptRuns", []):
            retained = next(row for row in jobs[job_id]["attemptRuns"] if row["runId"] == attempt["runId"])
            assert retained["dispatch"] == attempt["dispatch"]
    attempts = [row for job in jobs.values() for row in job.get("attemptRuns", [])]
    assert len([row for row in attempts if row.get("outcome") == "canceled"]) == 1
    assert len(attempts) == 4
    assert len({row["runId"] for row in attempts}) == 4
    save(evidence, "retained-cancellation", {"attemptRuns": attempts, "sourceUnchanged": True, "providerRequests": 0})


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    stage = sys.argv[3]
    if stage == "seed":
        investigation.seed(root, evidence, Path(sys.argv[4]).resolve())
        save(evidence, "cancellation-profile", {"cancelCall": 3, "liveProviderRequests": 0})
    elif stage == "admitted":
        admitted(root, evidence)
    elif stage == "canceled":
        canceled(root, evidence)
    elif stage == "hide-context":
        investigation.hide_context_output(root, evidence)
    elif stage == "restore-context":
        investigation.restore_context_output(root, evidence)
    else:
        investigation.verify(root, evidence, stage)
        if stage in ["completed", "final-report", "restart"]:
            verify_history(root, evidence)
