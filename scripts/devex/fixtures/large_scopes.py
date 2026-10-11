"""Nine owned boundaries, fixed work, budget halt and explicit Stop. No live inference."""
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from investigation_journey import seed as source_seed, read_native
from rejected_context import execute
from finite_scopes import scope

CAMPAIGN = "large-scopes"


def files(root):
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in root.glob("*/reader.rs")}


def queue(root):
    return json.loads((root / ".kuzushi/v3/campaigns" / CAMPAIGN / "queue.json").read_text())["jobs"]


def accounting(root):
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
        approvals = [json.loads(row[0]) for row in db.execute("select approval_json from investigation_allowance_revisions order by revision")]
        calls = db.execute("select count(*),sum(settled_at is null),sum(review) from investigation_call_reservations").fetchone()
        attempts = db.execute("select count(*) from investigation_work_attempts").fetchone()[0]
    return {"approvals": approvals, "committed": calls[0], "unresolved": calls[1] or 0,
            "review": calls[2] or 0, "attempts": attempts}


def dispatch(root, home, evidence, name):
    result = subprocess.run([os.environ["KUZUSHI_NATIVE_BIN"], "--target", str(root), "campaign", "run", CAMPAIGN,
        "--resume", "--workers", "1"], env={**os.environ, "HOME": str(home)}, capture_output=True, text=True, timeout=55)
    (evidence / (name + ".stdout.txt")).write_text(result.stdout)
    (evidence / (name + ".stderr.txt")).write_text(result.stderr)
    return result.returncode


def prepare(root, evidence, home, mode):
    source_seed(root, evidence, home)
    for name in ["main.rs", "app.py", "config.env"]:
        (root / name).unlink()
    ids = ["m0" + str(index) for index in range(1, 9)] + ["integration"]
    for name in ids:
        (root / name).mkdir()
        (root / name / "reader.rs").write_text("// OWNED " + name.upper() + "\n")
    repo = Path(__file__).resolve().parents[3]
    shutil.copyfile(repo / "scripts/devex/fixtures/large_scopes_provider.mjs", evidence / "provider.mjs")
    (evidence / "large-scope-settings.json").write_text(json.dumps({"mode": mode}))
    primary = [scope(name, name) for name in ids[:-1]]
    for entry in primary:
        entry["sharedDependencies"] = ["integration"]
    created = execute(root, home, evidence, "large-scopes-create", "pack:scopes", {"draft": {
        "schemaVersion": 1, "scopes": primary, "sharedScope": scope("integration", "integration"),
        "sharedDiscovery": True, "exclusions": []}})
    accepted = execute(root, home, evidence, "large-scopes-accept", "pack:scopes", {
        "operation": "accept", "proposalRef": created["reference"],
        "acknowledgements": {"inventoryLimitations": True, "exclusions": False, "overlappingDiscovery": False}})
    planned = execute(root, home, evidence, "large-scopes-plan", "campaign:study", {
        "campaignId": CAMPAIGN, "investigationId": "large-investigation", "scopeProposalRef": accepted["reference"],
        "scopeCases": [{"scopeId": name, "passes": 3} for name in ids],
        "scanInput": {"taskMode": "manual", "tasks": ["agentic"], "maxIterations": 1, "mcps": False, "threatModelRef": None}})
    execute(root, home, evidence, "large-scopes-approve", "campaign:approve-allowance", {
        "investigationId": "large-investigation", "expectedRevision": 0, "model": "openai-codex:gpt-5.5",
        "maxProviderCalls": 4, "protectedReviewCalls": 2, "reason": "Two owned intercepted requests; no live inference",
        "campaignId": CAMPAIGN, "campaignPlanSha256": planned["planSha256"], "campaignJobs": 27, "maxJobAttempts": 1})
    ledger = root / ".kuzushi/v3/workflow/phase-attempts.jsonl"
    ledger.parent.mkdir(parents=True, exist_ok=True)
    ledger.write_text(json.dumps({"event": "phase_checkpoint_skipped", "phase": "map",
        "targetSnapshot": {"target": str(root), "dirty": False}, "recordedAtUnix": 1}) + "\n")
    path = root / ".kuzushi/v3/campaigns" / CAMPAIGN / "plan.json"
    (evidence / "large-scope-before.json").write_text(json.dumps({"files": files(root), "planHash": hashlib.sha256(path.read_bytes()).hexdigest()}))
    (evidence / "large-scope-command.txt").write_text("campaign " + CAMPAIGN)
    if mode == "budget":
        assert dispatch(root, home, evidence, "first-stop") != 0
        verify(root, evidence, "budget-stopped")
        before = queue(root)
        assert dispatch(root, home, evidence, "resume-refused") != 0
        assert queue(root) == before


def await_jobs(root, predicate):
    deadline = time.monotonic() + 55
    while time.monotonic() < deadline:
        path = root / ".kuzushi/v3/campaigns" / CAMPAIGN / "queue.json"
        if path.exists():
            jobs = queue(root)
            if predicate(jobs):
                return jobs
        time.sleep(0.5)
    raise AssertionError("Owned fixed jobs did not reach their expected state")


def verify(root, evidence, stage):
    before = json.loads((evidence / "large-scope-before.json").read_text())
    path = root / ".kuzushi/v3/campaigns" / CAMPAIGN / "plan.json"
    assert files(root) == before["files"] and hashlib.sha256(path.read_bytes()).hexdigest() == before["planHash"]
    if stage.startswith("progress-"):
        expected = int(stage.removeprefix("progress-"))
        assert expected in [6, 12, 18, 24]
        jobs = await_jobs(root, lambda jobs: sum(job["state"] == "completed" for job in jobs.values()) >= expected)
        assert len(jobs) == 27
        state = accounting(root)
        assert state["approvals"][-1]["limits"] == {"maxProviderCalls": 29, "protectedReviewCalls": 2}
        (evidence / (stage + ".json")).write_text(json.dumps({"completed": sum(job["state"] == "completed" for job in jobs.values()), "fixedJobs": 27}))
        return
    if stage == "waiting":
        jobs = await_jobs(root, lambda jobs: (evidence / "waiting-bridge.json").exists())
    elif stage == "finished":
        jobs = await_jobs(root, lambda jobs: all(job["state"] == "completed" for job in jobs.values()))
    else:
        jobs = await_jobs(root, lambda jobs: all(job["state"] in ["completed", "parked"] for job in jobs.values()))
    assert len(jobs) == 27
    calls = [json.loads(line) for line in (evidence / "large-scope-calls.jsonl").read_text().splitlines()]
    state = accounting(root)
    stop = json.loads((evidence / "large-scope-settings.json").read_text())["mode"] == "stop"
    expected = 27 if stage == "finished" else 2
    assert len(calls) == state["committed"] == state["attempts"] == expected
    assert state["review"] == 0 and state["unresolved"] == (1 if stop else 0)
    complete = sum(job["state"] == "completed" for job in jobs.values())
    assert complete == (27 if stage == "finished" else 1 if stop else 2)
    if stage != "waiting":
        parked = [job for job in jobs.values() if job["state"] == "parked"]
        assert len(parked) == 27 - complete
        assert sum(job["attempts"] for job in parked) == (1 if stop else 0)
        assert all(job["dispatches"] == 0 and not job.get("runId") for job in parked if job["attempts"] == 0)
    last = state["approvals"][-1]
    assert last["limits"] == {"maxProviderCalls": 29 if stage == "finished" else 4, "protectedReviewCalls": 2}
    assert len(last["workPlan"]["jobs"]) == 27
    report = read_native(root, evidence, "occurrence-" + stage, ["findings", "batch", CAMPAIGN, "--json"])
    assert len(report["cases"]) == 9
    assert all(case["occurrence"]["planned"] == 3 for case in report["cases"])
    if stage == "finished":
        assert all(case["occurrence"]["completed"] == 3 and case["occurrence"]["rows"][0]["seen"] == 3 for case in report["cases"])
        assert all(job["attempts"] == 1 for job in jobs.values())
    if stage == "reader-pages":
        pages = "\n".join(path.read_text() for path in sorted(evidence.glob("*-report-page-*.txt")))
        for scope_id in ["m0" + str(index) for index in range(1, 9)] + ["integration"]:
            assert "Boundary " + scope_id + ":" in pages, "Unread boundary: " + scope_id
        for size in ["40x12", "60x20", "80x24", "120x36", "160x48", "96x89"]:
            captures = list(evidence.glob("*-selected-job-" + size + ".txt"))
            assert len(captures) == 1
            assert "integration-trial-003" in captures[0].read_text()
    if stop and stage != "waiting":
        for call in calls:
            try:
                os.kill(call["pid"], 0)
            except ProcessLookupError:
                pass
            else:
                raise AssertionError("Owned transport survived explicit Stop")
    (evidence / (stage + "-check.json")).write_text(json.dumps({"completed": complete, "fixedJobs": 27, "scopes": 9,
        "calls": expected, "unresolved": state["unresolved"], "liveRequests": 0, "sourceExecuted": False,
        "accounting": state}, indent=2))


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    if sys.argv[3] == "seed":
        prepare(root, evidence, Path(sys.argv[4]).resolve(), sys.argv[5])
    else:
        verify(root, evidence, sys.argv[3])
