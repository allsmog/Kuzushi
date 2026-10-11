"""Inspect owned finite planning and allowance contracts without model requests."""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path


def save(evidence, label, value):
    (evidence / (label + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def native(root, evidence, label, tool, value, succeeds=True):
    environment = dict(os.environ, HOME=str(evidence / "home"))
    for key in ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "KUZUSHI_MODEL", "KUZUSHI_LANGGRAPH_BRIDGE", "NODE_OPTIONS"]:
        environment.pop(key, None)
    result = subprocess.run([os.environ["KUZUSHI_NATIVE_BIN"], "--plain", "--target", str(root),
        "run", tool, "--input", json.dumps(value)], env=environment, capture_output=True, text=True, timeout=35)
    save(evidence, label, json.loads(result.stdout))
    (evidence / (label + ".stderr.txt")).write_text(result.stderr)
    assert (result.returncode == 0) == succeeds, (label, result.stderr)
    return json.loads(result.stdout)


def counts(root):
    path = root / ".kuzushi/v3/index.sqlite3"
    with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as connection:
        tables = {row[0] for row in connection.execute("select name from sqlite_master where type='table'")}
        names = ["finding_observations", "investigation_call_reservations", "investigation_work_attempts", "review_decisions"]
        return {name: connection.execute("select count(*) from " + name).fetchone()[0] if name in tables else 0 for name in names}


def source(root):
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in ["package.json", "main.rs"]}


def approve_input(draft):
    return {"investigationId":"owned", "expectedRevision":0, "model":"openai-codex:gpt-5.5",
        "maxProviderCalls":3, "protectedReviewCalls":1, "reason":"Owned offline accounting audit; no provider requests",
        "campaignId":"owned-finite", "campaignPlanSha256":draft["data"]["planSha256"],
        "campaignJobs":3, "maxJobAttempts":1}


def drafts(root, evidence):
    native(root, evidence, "missing-allowance", "campaign:allowance", {"investigationId":"missing"}, False)
    draft = native(root, evidence, "finite-draft", "campaign:study", {"campaignId":"owned-finite", "investigationId":"owned",
        "scanInput":{"taskMode":"manual","tasks":["license-scan"]}})
    assert draft["data"]["jobCount"] == 3 and draft["data"]["workers"] == 1
    context = native(root, evidence, "context-draft", "campaign:context-study", {"campaignId":"owned-context", "investigationId":"context-owned",
        "contextInput":{"methodology":"stride","model":"openai-codex:gpt-5.5","maxSourceBytes":4096,"maxOutputTokens":512}})
    plan = json.loads((root / ".kuzushi/v3/campaigns/owned-context/plan.json").read_text())
    assert len(plan["jobs"]) == plan["workers"] == 1
    assert context["data"]["input"]["activate"] is False and "No jobs started" in context["summary"]
    native(root, evidence, "unknown-study-option", "campaign:study", {"unknown":True,"scanInput":{}}, False)
    return draft


def refusals(root, evidence, approval):
    stale = native(root, evidence, "stale-approval", "campaign:approve-allowance", approval, False)
    assert "revision changed" in json.dumps(stale)
    wrong = dict(approval, expectedRevision=1, campaignPlanSha256="sha256:" + "0" * 64)
    native(root, evidence, "wrong-plan", "campaign:approve-allowance", wrong, False)
    invalid = dict(approval, expectedRevision=1, protectedReviewCalls=4)
    native(root, evidence, "invalid-limits", "campaign:approve-allowance", invalid, False)
    path = root / "main.rs"
    original = path.read_bytes()
    path.write_bytes(original + b"// Owned source drift for approval refusal.\n")
    try:
        native(root, evidence, "source-drift", "campaign:approve-allowance", dict(approval, expectedRevision=1), False)
    finally:
        path.write_bytes(original)


def snapshot(root, evidence, label):
    status = native(root, evidence, label, "campaign:allowance", {"investigationId":"owned","run_id":"legacy-no-provider-evidence"})
    allowance = status["data"]["allowance"]
    assert allowance["revision"] == 1 and allowance["committedCalls"] == allowance["unresolvedCalls"] == 0
    assert allowance["limits"] == {"maxProviderCalls":3,"protectedReviewCalls":1}
    assert status["data"]["runUsage"] is None and status["data"]["dollarCeilingEnforced"] is False
    assert "Calls available for context, scopes, scans and lessons: 2" in status["summary"]
    assert "unknown is not zero" in status["summary"]
    return allowance


def before(root, evidence):
    original = source(root)
    draft = drafts(root, evidence)
    approval = approve_input(draft)
    result = native(root, evidence, "approved", "campaign:approve-allowance", approval)
    assert len(result["data"]["allowance"]["workPlan"]["jobs"]) == 3
    refusals(root, evidence, approval)
    allowance = snapshot(root, evidence, "headless-status")
    assert source(root) == original and all(value == 0 for value in counts(root).values())
    assert not list((root / ".kuzushi/v3/campaigns").glob("*/queue.json"))
    save(evidence, "before", {"source":original,"counts":counts(root),"allowance":allowance})
    command = 'run campaign:allowance {"investigationId":"owned","run_id":"legacy-no-provider-evidence"}'
    (evidence / "read-command.txt").write_text(command)


def after(root, evidence):
    previous = json.loads((evidence / "before.json").read_text())
    assert snapshot(root, evidence, "restarted-status") == previous["allowance"]
    assert source(root) == previous["source"] and counts(root) == previous["counts"]
    assert not list((root / ".kuzushi/v3/campaigns").glob("*/queue.json"))
    save(evidence, "after", {"source":source(root),"counts":counts(root),"providerRequests":0,"jobsStarted":0})


root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
if sys.argv[3] == "before":
    before(root, evidence)
else:
    after(root, evidence)
