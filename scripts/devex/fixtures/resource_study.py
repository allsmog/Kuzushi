"""Observed per-case resource calibration over owned source and intercepted transport."""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from investigation_journey import seed as source_seed
from rejected_context import execute
from scoped_discovery import scope
from secret_settings import ledger

PRIOR = "resource-prior"
NEXT = "resource-next"
INVESTIGATION = "resource-accounting"


def source_hashes(root):
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in root.glob("*/reader.rs")}


def accounting(root, evidence):
    with ledger(root, evidence) as db:
        rows = db.execute("select count(*),sum(settled_at is null) from investigation_call_reservations").fetchone()
    return {"committed": rows[0], "unresolved": rows[1] or 0}


def plan_digest(root):
    path = root / ".kuzushi/v3/campaigns" / NEXT / "plan.json"
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare(root, evidence, home):
    source_seed(root, evidence, home)
    for name in ["main.rs", "app.py", "config.env"]:
        (root / name).unlink()
    for name in ["m01", "m02", "integration"]:
        (root / name).mkdir()
        (root / name / "reader.rs").write_text("// OWNED " + name.upper() + "\n")
    repo = Path(__file__).resolve().parents[3]
    shutil.copyfile(repo / "scripts/devex/fixtures/large_scopes_provider.mjs", evidence / "provider.mjs")
    (evidence / "large-scope-settings.json").write_text(json.dumps({"mode": "budget"}))
    primary = [scope(name, name) for name in ["m01", "m02"]]
    for entry in primary:
        entry["sharedDependencies"] = ["shared"]
    primary.append(scope("integration", "integration"))
    created = execute(root, home, evidence, "resource-scopes", "pack:scopes", {"draft": {
        "schemaVersion": 1, "scopes": primary, "sharedScope": scope("shared", "integration"),
        "sharedDiscovery": False, "exclusions": []}})
    accepted = execute(root, home, evidence, "resource-accepted", "pack:scopes", {
        "operation": "accept", "proposalRef": created["reference"],
        "acknowledgements": {"inventoryLimitations": True, "exclusions": False, "overlappingDiscovery": False}})
    selected = {"investigationId": INVESTIGATION, "scopeProposalRef": accepted["reference"],
                "scopeCases": [{"scopeId": name, "passes": 3} for name in ["m01", "m02"]],
                "scanInput": {"taskMode": "manual", "tasks": ["agentic"], "maxIterations": 1,
                              "mcps": False, "threatModelRef": None, "scanContextRef": None}}
    prior = execute(root, home, evidence, "resource-prior", "campaign:study", {**selected, "campaignId": PRIOR})
    approval = execute(root, home, evidence, "resource-prior-approval", "campaign:approve-allowance", {
        "investigationId": INVESTIGATION, "expectedRevision": 0, "model": "openai-codex:gpt-5.5",
        "maxProviderCalls": 8, "protectedReviewCalls": 2, "reason": "Six owned intercepted passes, no live inference",
        "campaignId": PRIOR, "campaignPlanSha256": prior["planSha256"], "campaignJobs": 6, "maxJobAttempts": 1})
    with (evidence / "resource-prior.stdout.txt").open("w") as stdout, (evidence / "resource-prior.stderr.txt").open("w") as stderr:
        process = subprocess.Popen([os.environ["KUZUSHI_NATIVE_BIN"], "--target", str(root), "campaign", "run", PRIOR,
                                    "--resume", "--workers", "1"], env={**os.environ, "HOME": str(home)},
                                   stdout=stdout, stderr=stderr, text=True)
        (evidence / "resource-prior-pid.json").write_text(json.dumps({"pid": process.pid}))
        deadline = time.monotonic() + 180
        while process.poll() is None and time.monotonic() < deadline:
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
        assert process.poll() is not None, "Observation expired; inspect the same recorded dispatcher PID before continuing"
        assert process.returncode == 0, (evidence / "resource-prior.stderr.txt").read_text()
    next_plan = execute(root, home, evidence, "resource-next", "campaign:study", {
        **selected, "campaignId": NEXT, "resourceBaselineCampaignId": PRIOR})
    quote = next_plan["resourceEvidence"]
    assert len(quote["cases"]) == 2
    assert all(entry["callsPerPass"] == [1, 1] and len(entry["runIds"]) == 3 for entry in quote["cases"])
    assert all(entry["costPerPassUsd"] is None for entry in quote["cases"])
    before = {"files": source_hashes(root), "accounting": accounting(root, evidence),
              "planSha256": next_plan["planSha256"], "planFileSha256": plan_digest(root),
              "approvedWorkPlan": approval["allowance"]["workPlan"]}
    assert before["accounting"] == {"committed": 6, "unresolved": 0}
    (evidence / "resource-before.json").write_text(json.dumps(before))
    (evidence / "resource-command.txt").write_text("campaign " + NEXT)


def verify(root, evidence, stage):
    before = json.loads((evidence / "resource-before.json").read_text())
    assert source_hashes(root) == before["files"]
    assert accounting(root, evidence) == before["accounting"]
    assert plan_digest(root) == before["planFileSha256"]
    allowance = verify_allowance(root, evidence, stage, before)
    calls = (evidence / "large-scope-calls.jsonl").read_text().splitlines()
    assert len(calls) == 6
    campaign = root / ".kuzushi/v3/campaigns" / NEXT
    assert not (campaign / "queue.json").exists(), "Resource review must not start discovery"
    (evidence / (stage + "-check.json")).write_text(json.dumps({"committedCalls": 6, "newJobsStarted": 0,
        "liveRequests": 0, "sourceExecuted": False, "knownCases": 2, "dollarScenario": None,
        "allowanceRevision": allowance["revision"], "limits": allowance["limits"],
        "approvedCampaign": allowance["workPlan"]["campaignId"], "planUnchanged": True}))


def verify_allowance(root, evidence, stage, before):
    data = execute(root, evidence / "home", evidence, "resource-allowance-" + stage,
                   "campaign:allowance", {"investigationId": INVESTIGATION})
    allowance = data["allowance"]
    assert allowance["revision"] == 1
    assert allowance["limits"] == {"maxProviderCalls": 8, "protectedReviewCalls": 2}
    assert allowance["workPlan"] == before["approvedWorkPlan"]
    assert allowance["committedCalls"] == 6
    assert allowance["reviewCalls"] == allowance["unresolvedCalls"] == 0
    return allowance


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    if sys.argv[3] == "seed":
        prepare(root, evidence, Path(sys.argv[4]).resolve())
    else:
        verify(root, evidence, sys.argv[3])
