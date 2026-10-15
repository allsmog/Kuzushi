"""Approved remaining Review request on the retained owned inert fixture."""
import hashlib
import json
import sys
import time
from pathlib import Path

from approved_live_review import MODEL, inspect_existing, save
from live_investigation import CONTROL, FIXTURE, SCAN, invariant, native
from secret_settings import ledger

CAMPAIGN = "live-owned-review-preserved-20261011"
OLD_CAMPAIGN = "live-owned-review-raw-20261010"
INVESTIGATION = "live-owned-investigation-20261010"
PROPOSAL = Path("/tmp/kuzushi-review-recovery-20261011/follow-up-proposal")
DIGEST = "sha256:576f7f233c1993413a068a77ad7d33ccedc7ef12c6457b5dda59420229941bcd"


def historical_receipts(root):
    job = json.loads((root / ".kuzushi/v3/campaigns" / OLD_CAMPAIGN / "queue.json").read_text())["jobs"]["review-001"]
    run = root / ".kuzushi/v3/runs" / job["runId"]
    return {name: hashlib.sha256((run / name).read_bytes()).hexdigest()
            for name in ["run.json", "result.json", "items.jsonl"]}


def prepare(root, evidence):
    inspect_existing(root, evidence)
    folder = root / ".kuzushi/v3/campaigns" / CAMPAIGN
    assert not (folder / "queue.json").exists(), "Consumed or started plans cannot be prepared again"
    plan = json.loads((folder / "plan.json").read_text())
    assert plan["workers"] == 1 and len(plan["jobs"]) == 1 and plan["model"] == MODEL
    assert plan["jobs"][0]["tool"] == "triage:run" and plan["jobs"][0]["input"]["votes"] == 1
    assert plan["jobs"][0]["input"]["threatModelRef"] == json.loads((CONTROL / "context-reference.json").read_text())
    fields = json.loads((PROPOSAL / "proposed-approval-input.json").read_text())
    assert fields["campaignId"] == CAMPAIGN and fields["campaignPlanSha256"] == DIGEST
    assert fields["maxProviderCalls"] == 6 and fields["protectedReviewCalls"] == 2
    assert fields["campaignJobs"] == fields["maxJobAttempts"] == 1 and fields["model"] == MODEL
    save(evidence, "historical-receipts-before", historical_receipts(root))
    approved = native(root, evidence, "approved-preserved-review", "campaign:approve-allowance", fields)["allowance"]
    assert approved["committedCalls"] == 5 and approved["unresolvedCalls"] == 0
    assert approved["workPlan"]["planSha256"] == DIGEST
    save(evidence, "approved-repair-terms", {"humanApproval":"Approve this bounded Review",
        "additionalRequestsIncludingRetries":1,"totalRequestCeiling":6,"model":MODEL,
        "reasoning":"low","workers":1,"jobs":1,"attempts":1,"dollars":"unknown"})


def wait_terminal(root, evidence):
    path = root / ".kuzushi/v3/campaigns" / CAMPAIGN / "queue.json"
    deadline = time.monotonic() + 240
    while time.monotonic() < deadline:
        if path.exists():
            jobs = json.loads(path.read_text())["jobs"]
            assert len(jobs) == 1
            if all(job["state"] not in ["planned", "running"] for job in jobs.values()):
                return verify(root, evidence, "completed")
        time.sleep(1)
    raise RuntimeError("Review observation timed out. Inspect the existing job; never relaunch it.")


def inspect_completed(root, evidence):
    previous = Path("/tmp/kuzushi-blocked-review-20261011/actual-review-native/20261011-171054/J212")
    for name in ["manifest-before", "human-decision-before", "historical-receipts-before", "approved-repair-terms"]:
        save(evidence, name, json.loads((previous / (name + ".json")).read_text()))
    verify(root, evidence, "existing")


def verify(root, evidence, stage):
    invariant(root, evidence)
    assert historical_receipts(root) == json.loads((evidence / "historical-receipts-before.json").read_text())
    jobs = json.loads((root / ".kuzushi/v3/campaigns" / CAMPAIGN / "queue.json").read_text())["jobs"]
    assert len(jobs) == 1
    job = jobs["review-001"]
    assert job["state"] == "completed" and job["attempts"] == job["dispatches"] == 1, job
    run = root / ".kuzushi/v3/runs" / job["runId"]
    result = json.loads((run / "result.json").read_text())
    calls = json.loads((run / "run.json").read_text())["llmCalls"]
    assert len(calls) == 1 and calls[0]["model"] == MODEL and calls[0]["callAttempted"]
    assert result["status"] == "completed" and result["data"]["successful"] == 1
    assert result["data"]["persistenceFailures"] == 0 and result["data"]["unappliedOpinions"] == 1
    assert result["data"]["findings"][0]["decisionApplied"] is False
    allowance = native(root, evidence, stage + "-allowance", "campaign:allowance", {"investigationId":INVESTIGATION})["allowance"]
    assert allowance["committedCalls"] == 6 and allowance["reviewCalls"] == 2 and allowance["unresolvedCalls"] == 0
    with ledger(root, evidence) as db:
        counts = {table:db.execute("select count(*) from " + table).fetchone()[0] for table in ["investigation_call_reservations","investigation_work_attempts","finding_observations","review_decisions"]}
    assert counts == {"investigation_call_reservations":6,"investigation_work_attempts":8,"finding_observations":3,"review_decisions":1}, counts
    verify_human(root, evidence, stage)
    save(evidence, stage + "-check", {"counts":counts,"committedCalls":6,"unresolvedCalls":0,
        "humanDecisionPreserved":True,"sourceUnchanged":True,"originalReceiptUnchanged":True,
        "sourceExecuted":False,"planExpanded":False,"dollars":"unknown","runId":job["runId"]})


def verify_human(root, evidence, stage):
    output = root / ".kuzushi/reports" / ("preserved-review-" + stage + ".json")
    native(root, evidence, stage + "-export", "workspace:export-findings", {"campaignId":SCAN,"format":"json","output":str(output)})
    report = json.loads(output.read_text())
    finding = report["findings"][0]
    assert {k:v for k,v in finding.items() if k.startswith("reviewDecision")} == json.loads((evidence / "human-decision-before.json").read_text())
    assert hashlib.sha256((root / ".kuzushi/threat-models/manifest.json").read_bytes()).hexdigest() == json.loads((evidence / "manifest-before.json").read_text())["sha256"]
    assert len(finding["provenance"]["sourceHistory"]) == 3
    save(evidence, stage + "-findings", report)


if __name__ == "__main__":
    root,evidence,stage = Path(sys.argv[1]).resolve(),Path(sys.argv[2]).resolve(),sys.argv[3]
    assert root == FIXTURE / "target"
    evidence.mkdir(parents=True,exist_ok=True)
    if stage == "prepare": prepare(root,evidence)
    elif stage == "wait": wait_terminal(root,evidence)
    elif stage == "inspect": inspect_completed(root,evidence)
    else: verify(root,evidence,stage)
