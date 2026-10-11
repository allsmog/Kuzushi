"""Owned source-analysis Stop receipt, with all model transport intercepted."""
import hashlib
import json
import os
import shutil
import sys
import time
from pathlib import Path
from budget_recovery import accounting
from context_matrix import seed as context_seed
from rejected_context import execute

CAMPAIGN = "stop-matrix"


def seed(root, evidence, home):
    context_seed(root, evidence, home)
    repo = Path(__file__).resolve().parents[3]
    shutil.copyfile(repo / "scripts/devex/fixtures/stop_provider.mjs", evidence / "provider.mjs")
    refs = json.loads((evidence / "before.json").read_text())["refs"]
    plan = execute(root, home, evidence, "stop-plan", "campaign:study", {
        "campaignId": CAMPAIGN, "investigationId": "stop-investigation", "baselineCaseId": "alpha",
        "contextCases": [{"id": name.lower(), "label": name, "threatModelRef": refs[name]} for name in ["Alpha", "Beta", "Gamma"]],
        "scanInput": {"taskMode": "manual", "tasks": ["agentic"], "maxIterations": 1, "mcps": False}})
    execute(root, home, evidence, "stop-approval", "campaign:approve-allowance", {
        "investigationId": "stop-investigation", "expectedRevision": 0, "model": "openai-codex:gpt-5.5",
        "maxProviderCalls": 4, "protectedReviewCalls": 2, "reason": "Two intercepted requests; stop the second; no live inference",
        "campaignId": CAMPAIGN, "campaignPlanSha256": plan["planSha256"], "campaignJobs": 9, "maxJobAttempts": 1})
    ledger = root / ".kuzushi/v3/workflow/phase-attempts.jsonl"
    ledger.parent.mkdir(parents=True, exist_ok=True)
    ledger.write_text(json.dumps({"event": "phase_checkpoint_skipped", "phase": "map", "targetSnapshot": {"target": str(root), "dirty": False}, "recordedAtUnix": 1}) + "\n")
    (evidence / "stop-command.txt").write_text("campaign " + CAMPAIGN)


def verify(root, evidence, stage):
    before = json.loads((evidence / "before.json").read_text())
    assert hashlib.sha256((root / "main.rs").read_bytes()).hexdigest() == before["sourceSha256"]
    assert hashlib.sha256((root / ".kuzushi/threat-model.json").read_bytes()).hexdigest() == before["activeMirrorSha256"]
    directory = root / ".kuzushi/v3/campaigns" / CAMPAIGN
    for _ in range(30):
        path = directory / "queue.json"
        jobs = json.loads(path.read_text())["jobs"] if path.exists() else {}
        waiting = (evidence / "waiting-bridge.json").exists()
        settled = jobs and all(job["state"] in ["completed", "parked"] for job in jobs.values())
        if waiting and (stage == "waiting" or settled): break
        time.sleep(0.5)
    assert len(jobs) == 9 and waiting
    requests = [json.loads(line) for line in (evidence / "stop-calls.jsonl").read_text().splitlines()]
    assert len(requests) == 2
    budget = accounting(root)
    assert budget["calls"] == 2 and budget["attempts"] == 2 and budget["unresolved"] == 1
    assert budget["limits"] == {"maxProviderCalls": 4, "protectedReviewCalls": 2}
    if stage != "waiting":
        assert sum(job["state"] == "completed" for job in jobs.values()) == 1
        parked = [job for job in jobs.values() if job["state"] == "parked"]
        assert len(parked) == 8 and sum(job["attempts"] for job in parked) == 1
        assert all(job["reason"] == "interrupted" for job in parked)
        assert all(job["dispatches"] == 0 for job in parked if job["attempts"] == 0)
        for pid in [request["pid"] for request in requests]:
            try: os.kill(pid, 0)
            except ProcessLookupError: pass
            else: raise AssertionError(f"Owned transport child {pid} survived Stop")
        events = [json.loads(line) for line in (directory / "events.jsonl").read_text().splitlines()]
        assert sum(event["event"] == "job-start" for event in events) == 2
        assert any(event["event"] == "dispatch-end" for event in events)
    (evidence / (stage + "-stop-check.json")).write_text(json.dumps({"stage": stage, "providerRequestsIntercepted": 2, "liveRequests": 0,
        "sourceExecuted": False, "accounting": budget, "jobs": jobs}, indent=2) + "\n")


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "seed": seed(root, evidence, Path(sys.argv[4]).resolve())
    else: verify(root, evidence, stage)
