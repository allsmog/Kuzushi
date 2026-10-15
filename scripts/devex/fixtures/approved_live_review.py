"""One explicitly approved OAuth Review on the retained owned inert fixture."""
import hashlib
import json
import sys
import time
from pathlib import Path
from live_investigation import CONTROL, FIXTURE, SCAN, invariant, native
from secret_settings import ledger

CAMPAIGN = "live-owned-review-raw-20261010"
DIGEST = "sha256:f39838407a9617d1a1c8e2c4959061000dccf0965d94f7381a66388beb49e409"
MODEL = "openai-codex:gpt-6-luna"
PROPOSAL = Path("/private/tmp/kuzushi-live-review-20261010")


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def prepare(root, evidence):
    assert root == FIXTURE / "target"
    invariant(root, evidence)
    fields = json.loads((PROPOSAL / "proposed-approval-input.json").read_text())
    assert fields["campaignId"] == CAMPAIGN and fields["campaignPlanSha256"] == DIGEST
    assert fields["maxProviderCalls"] == 6 and fields["protectedReviewCalls"] == 2
    assert fields["campaignJobs"] == fields["maxJobAttempts"] == 1
    assert fields["model"] == MODEL
    plan = json.loads((root / ".kuzushi/v3/campaigns" / CAMPAIGN / "plan.json").read_text())
    assert len(plan["jobs"]) == 1 and plan["workers"] == 1
    assert plan["model"] == MODEL and plan["jobs"][0]["tool"] == "triage:run"
    assert plan["jobs"][0]["input"]["votes"] == 1
    assert plan["jobs"][0]["input"]["threatModelRef"] == json.loads((CONTROL / "context-reference.json").read_text())
    assert not (root / ".kuzushi/v3/campaigns" / CAMPAIGN / "queue.json").exists()
    status = native(root, evidence, "before-allowance", "campaign:allowance", {"investigationId":fields["investigationId"]})
    assert status["allowance"]["committedCalls"] == 4 and status["allowance"]["unresolvedCalls"] == 0
    baseline = json.loads((root / ".kuzushi/reports/findings.json").read_text())["findings"][0]
    save(evidence, "human-decision-before", {k:v for k,v in baseline.items() if k.startswith("reviewDecision")})
    manifest = root / ".kuzushi/threat-models/manifest.json"
    save(evidence, "manifest-before", {"sha256":hashlib.sha256(manifest.read_bytes()).hexdigest()})
    approval = native(root, evidence, "approved-allowance", "campaign:approve-allowance", fields)
    allowance = approval["allowance"]
    assert allowance["limits"]["maxProviderCalls"] == 6 and allowance["committedCalls"] == 4
    save(evidence, "approved-terms", {"planSha256":DIGEST,"model":MODEL,"reasoning":"low","jobs":1,"workers":1,"maxAttempts":1,"additionalRequestsIncludingRetries":2,"dollars":"unknown","humanApproval":"Explicit bounded Review reply"})



def resume(root, evidence):
    invariant(root, evidence)
    previous = Path("/tmp/kuzushi-approved-live-review-20261011/native/20261011-144755/J208")
    for name in ["manifest-before", "human-decision-before", "approved-terms"]:
        save(evidence, name, json.loads((previous / (name + ".json")).read_text()))
    status = native(root, evidence, "resume-allowance", "campaign:allowance", {"investigationId":"live-owned-investigation-20261010"})["allowance"]
    assert status["limits"] == {"maxProviderCalls":6,"protectedReviewCalls":2}
    assert status["committedCalls"] == 4 and status["unresolvedCalls"] == 0
    assert status["workPlan"]["planSha256"] == DIGEST
    jobs = json.loads((root / ".kuzushi/v3/campaigns" / CAMPAIGN / "queue.json").read_text())["jobs"]
    assert len(jobs) == 1
    assert all(j["attempts"] == 0 and j["state"] == "parked" and j["reason"] == "allowance-exhausted" for j in jobs.values())


def inspect_existing(root, evidence):
    previous = Path("/tmp/kuzushi-approved-live-review-20261011/native/20261011-144755/J208")
    for name in ["manifest-before", "human-decision-before", "approved-terms"]:
        save(evidence, name, json.loads((previous / (name + ".json")).read_text()))
    verify(root, evidence, "existing")


def wait_terminal(root, evidence):
    queue = root / ".kuzushi/v3/campaigns" / CAMPAIGN / "queue.json"
    deadline = time.monotonic() + 240
    last_notice = 0
    while time.monotonic() < deadline:
        if queue.exists():
            jobs = json.loads(queue.read_text())["jobs"]
            assert len(jobs) == 1
            if all(j["state"] not in ["planned", "running"] for j in jobs.values()):
                save(evidence, "terminal-jobs", jobs)
                return verify(root, evidence, "completed")
            if time.monotonic() - last_notice > 10:
                print("Observed existing Review job: " + str({k:v["state"] for k,v in jobs.items()}), flush=True)
                last_notice = time.monotonic()
        time.sleep(1)
    raise RuntimeError("Existing Review is not terminal. Inspect its process and receipts; never restart from an observation timeout.")


def verify(root, evidence, stage):
    invariant(root, evidence)
    queue = json.loads((root / ".kuzushi/v3/campaigns" / CAMPAIGN / "queue.json").read_text())
    jobs = queue["jobs"]
    assert len(jobs) == 1 and all(j["attempts"] == 1 for j in jobs.values())
    assert all(j["state"] not in ["planned", "running"] for j in jobs.values())
    with ledger(root, evidence) as db:
        counts = {table:db.execute("select count(*) from " + table).fetchone()[0] for table in ["investigation_call_reservations","investigation_work_attempts","finding_observations","review_decisions"]}
    assert 4 <= counts["investigation_call_reservations"] <= 6
    assert counts["investigation_work_attempts"] == 7 and counts["finding_observations"] == 3
    assert counts["review_decisions"] == 1
    status = native(root, evidence, stage + "-allowance", "campaign:allowance", {"investigationId":"live-owned-investigation-20261010"})
    allowance = status["allowance"]
    assert allowance["limits"]["maxProviderCalls"] == 6
    assert 4 <= allowance["committedCalls"] <= 6
    output = root / ".kuzushi/reports" / ("bounded-review-" + stage + ".json")
    native(root, evidence, stage + "-export", "workspace:export-findings", {"campaignId":SCAN,"format":"json","output":str(output)})
    report = json.loads(output.read_text())
    save(evidence, stage + "-findings", report)
    finding = report["findings"][0]
    assert finding["reviewDecisionAuthor"] == "human"
    assert finding["reviewDecision"] == "rejected_false_positive"
    assert {k:v for k,v in finding.items() if k.startswith("reviewDecision")} == json.loads((evidence / "human-decision-before.json").read_text())
    assert hashlib.sha256((root / ".kuzushi/threat-models/manifest.json").read_bytes()).hexdigest() == json.loads((evidence / "manifest-before.json").read_text())["sha256"]
    assert len(finding["provenance"]["sourceHistory"]) == 3
    save(evidence, stage + "-check", {"counts":counts,"committedCalls":allowance["committedCalls"],"unresolvedCalls":allowance["unresolvedCalls"],"jobs":{k:v["state"] for k,v in jobs.items()},"humanDecisionPreserved":True,"sourceUnchanged":True,"sourceExecuted":False,"planExpanded":False,"dollars":"unknown"})
    if stage in ["existing", "reported", "restarted"]:
        assert counts["investigation_call_reservations"] == allowance["committedCalls"] == 5
        assert allowance["reviewCalls"] == 1 and allowance["unresolvedCalls"] == 0
        job = jobs["review-001"]
        assert job["state"] == "failed" and job["dispatches"] == 1
        run = root / ".kuzushi/v3/runs" / job["runId"]
        calls = json.loads((run / "run.json").read_text())["llmCalls"]
        result = json.loads((run / "result.json").read_text())
        assert len(calls) == 1 and calls[0]["model"] == MODEL and calls[0]["callAttempted"]
        assert result["status"] == "failed" and result["data"]["persistenceFailures"] == 1
        save(evidence, stage + "-historical-run", {"runId":job["runId"],"calls":len(calls),"model":MODEL,"status":result["status"],"receiptRewritten":False,"newRequests":0})


if __name__ == "__main__":
    root,evidence,stage = Path(sys.argv[1]).resolve(),Path(sys.argv[2]).resolve(),sys.argv[3]
    assert root == FIXTURE / "target"
    evidence.mkdir(parents=True,exist_ok=True)
    if stage == "prepare": prepare(root,evidence)
    elif stage == "resume": resume(root,evidence)
    elif stage == "inspect": inspect_existing(root,evidence)
    elif stage == "wait": wait_terminal(root,evidence)
    else: verify(root,evidence,stage)
