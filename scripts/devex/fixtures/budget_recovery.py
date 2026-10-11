"""Real owned source-analysis dispatch with intercepted transport and finite calls."""
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from context_matrix import seed as context_seed
from rejected_context import execute

CAMPAIGN = "budget-matrix"


def calls(evidence):
    path = evidence / "budget-calls.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def queue(root):
    return json.loads((root / ".kuzushi/v3/campaigns" / CAMPAIGN / "queue.json").read_text())["jobs"]


def accounting(root):
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
        approval = json.loads(db.execute("select approval_json from investigation_allowance_revisions order by revision desc limit 1").fetchone()[0])
        count = db.execute("select count(*),sum(settled_at is null) from investigation_call_reservations").fetchone()
        attempts = db.execute("select count(*) from investigation_work_attempts").fetchone()[0]
    return {"calls": count[0], "unresolved": count[1] or 0, "attempts": attempts, "limits": approval["limits"]}


def dispatch(root, home, evidence, label):
    result = subprocess.run([os.environ["KUZUSHI_NATIVE_BIN"], "--target", str(root),
        "campaign", "run", CAMPAIGN, "--resume", "--workers", "1"],
        env=dict(os.environ, HOME=str(home)), text=True, capture_output=True, timeout=90)
    (evidence / (label + ".log")).write_text(result.stdout + result.stderr)
    return result.returncode


def seed(root, evidence, home):
    context_seed(root, evidence, home)
    repo = Path(__file__).resolve().parents[3]
    shutil.copyfile(repo / "scripts/devex/fixtures/budget_provider.mjs", evidence / "provider.mjs")
    (evidence / "budget-target.txt").write_text(str(root))
    refs = json.loads((evidence / "before.json").read_text())["refs"]
    plan = execute(root, home, evidence, "budget-plan", "campaign:study", {
        "campaignId": CAMPAIGN, "investigationId": "budget-investigation", "baselineCaseId": "alpha",
        "contextCases": [{"id": name.lower(), "label": name, "threatModelRef": refs[name]} for name in ["Alpha", "Beta", "Gamma"]],
        "scanInput": {"taskMode": "manual", "tasks": ["agentic"], "maxIterations": 1, "mcps": False}})
    execute(root, home, evidence, "budget-approval", "campaign:approve-allowance", {
        "investigationId": "budget-investigation", "expectedRevision": 0, "model": "openai-codex:gpt-5.5",
        "maxProviderCalls": 4, "protectedReviewCalls": 2, "reason": "Two intercepted requests, then stop; no live inference",
        "campaignId": CAMPAIGN, "campaignPlanSha256": plan["planSha256"], "campaignJobs": 9, "maxJobAttempts": 1})
    ledger = root / ".kuzushi/v3/workflow/phase-attempts.jsonl"
    ledger.parent.mkdir(parents=True, exist_ok=True)
    ledger.write_text(json.dumps({"event": "phase_checkpoint_skipped", "phase": "map",
        "targetSnapshot": {"target": str(root), "dirty": False}, "recordedAtUnix": 1}) + "\n")
    assert dispatch(root, home, evidence, "first-budget-stop") != 0
    verify(root, evidence, "stopped")
    before = queue(root)
    history = ledger.read_bytes()
    assert dispatch(root, home, evidence, "resume-without-new-allowance") != 0
    assert queue(root) == before and ledger.read_bytes() == history
    (evidence / "budget-command.txt").write_text("campaign " + CAMPAIGN)


def verify(root, evidence, stage):
    before = json.loads((evidence / "before.json").read_text())
    assert hashlib.sha256((root / "main.rs").read_bytes()).hexdigest() == before["sourceSha256"]
    assert hashlib.sha256((root / ".kuzushi/threat-model.json").read_bytes()).hexdigest() == before["activeMirrorSha256"]
    jobs = queue(root)
    assert len(jobs) == 9
    complete = sum(job["state"] == "completed" for job in jobs.values())
    if stage != "finished":
        assert complete == 2
        parked = [job for job in jobs.values() if job["state"] == "parked"]
        assert len(parked) == 7
        assert all(job["reason"] == "allowance-exhausted" and job["attempts"] == 0
                   and job["dispatches"] == 0 and not job.get("runId") for job in parked)
        expected = 2
    else:
        for _ in range(60):
            if all(job["state"] == "completed" for job in queue(root).values()): break
            time.sleep(1)
        assert all(job["state"] == "completed" and job["attempts"] == 1 for job in queue(root).values())
        expected = 9
    assert len(calls(evidence)) == expected
    budget = accounting(root)
    assert budget["calls"] == expected and budget["attempts"] == expected and budget["unresolved"] == 0
    assert budget["limits"] == {"maxProviderCalls": 11 if stage == "finished" else 4, "protectedReviewCalls": 2}
    (evidence / (stage + "-budget-check.json")).write_text(json.dumps({"completed": expected,
        "providerRequestsIntercepted": expected, "liveRequests": 0, "sourceExecuted": False,
        "pendingJobsUnstarted": 9 - expected, "accounting": budget}, indent=2) + "\n")


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "seed": seed(root, evidence, Path(sys.argv[4]).resolve())
    else: verify(root, evidence, stage)
