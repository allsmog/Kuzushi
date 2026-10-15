"""Inspect the completed approved Review without creating or dispatching work."""
import hashlib
import json
import sys
from pathlib import Path

from live_application_case import FIXTURE, OWNER, source_hashes
from secret_settings import ledger, save

SCAN = "live-application-scans-20261015"
REVIEW = "live-application-review-20261015"
MODEL = "openai-codex:gpt-6-luna"


def verify(root, evidence, stage):
    assert root == FIXTURE / "target"
    control = FIXTURE / "review-proposed-20261015"
    before = json.loads((control / "before.json").read_text())
    assert source_hashes(root) == before["source"]
    manifest = root / ".kuzushi/threat-models/manifest.json"
    assert hashlib.sha256(manifest.read_bytes()).hexdigest() == before["contextManifestSha256"]
    assert json.loads(manifest.read_text()).get("active") is None
    config = OWNER / ".kuzushi/v3/config.toml"
    assert hashlib.sha256(config.read_bytes()).hexdigest() == before["operatorConfigSha256"]
    config = FIXTURE / "home/.kuzushi/v3/config.toml"
    assert hashlib.sha256(config.read_bytes()).hexdigest() == before["homeConfigSha256"]
    campaign = root / ".kuzushi/v3/campaigns" / REVIEW
    plan = json.loads((campaign / "plan.json").read_text())
    jobs = json.loads((campaign / "queue.json").read_text())["jobs"]
    assert plan["workers"] == len(plan["jobs"]) == len(jobs) == 1
    job = jobs["review-001"]
    assert job["state"] == "completed" and job["attempts"] == job["dispatches"] == 1
    run = root / ".kuzushi/v3/runs" / job["runId"]
    result = json.loads((run / "result.json").read_text())
    assert result["status"] == "completed"
    data = result["data"]
    assert data["attempted"] == data["successful"] == data["needsReview"] == 1
    assert data["failed"] == data["persistenceFailures"] == data["unappliedOpinions"] == 0
    assert data["providerSpendUnresolved"] is True
    opinion = data["findings"][0]
    assert opinion["verdict"] == "needs_review" and opinion["confidence"] == 0.25
    assert opinion["decisionApplied"] is True and opinion["cached"] is False
    assert "no source excerpts" in opinion["rationale"]
    calls = json.loads((run / "run.json").read_text())["llmCalls"]
    assert len(calls) == 1 and calls[0]["model"] == MODEL and calls[0]["callAttempted"]
    with ledger(root, evidence) as db:
        rows = db.execute("select call_json,settled_at,review from investigation_call_reservations").fetchall()
        assert len(rows) == 4 and all(settled is not None for _, settled, _ in rows)
        assert sum(review for _, _, review in rows) == 1
        assert all(json.loads(row[0])["model"] == MODEL for row in rows)
        assert db.execute("select count(*) from finding_observations").fetchone()[0] == 3
        assert db.execute("select count(*) from investigation_work_attempts").fetchone()[0] == 4
        assert db.execute("select count(*) from review_decisions").fetchone()[0] == 1
        assert db.execute("select author from review_decisions").fetchone()[0] == "auto"
        approval = json.loads(db.execute("select approval_json from investigation_allowance_revisions order by revision desc limit 1").fetchone()[0])
        assert approval["limits"] == {"maxProviderCalls": 5, "protectedReviewCalls": 2}
        assert approval["workPlan"]["campaignId"] == REVIEW
    if stage in ["exported", "restarted"]:
        report = json.loads((root / ".kuzushi/reports/findings.json").read_text())
        finding = report["findings"][0]
        assert report["count"] == 1
        assert finding["reviewDecision"] == "needs_review"
        assert finding["reviewDecisionAuthor"] == "auto" and finding["confidence"] == 0.25
        receipt = report["metadata"]["investigation"]
        assert receipt["campaignId"] == SCAN and receipt["observationCount"] == 3
        assert receipt["reviewedCount"] == receipt["confirmedCount"] == 0
        assert receipt["occurrence"]["rows"][0]["seen"] == 3
        accounting = receipt["allowance"]["currentInvestigation"]
        assert accounting["committedCalls"] == 4 and accounting["reviewCalls"] == 1
        assert accounting["unresolvedCalls"] == 0 and accounting["cost"]["observedUsd"] is None
    save(evidence, stage + "-verified", {"completedReviewJobs": 1, "providerRequests": 4,
        "newReviewRequests": 1, "cumulativeExperimentRequests": 12, "observations": 3,
        "humanDecisions": 0, "automaticDecisions": 1, "confirmedFindings": 0,
        "sourceUnchanged": True, "sourceExecuted": False, "helperProductDispatches": 0})


if __name__ == "__main__":
    root, evidence = [Path(p).resolve() for p in sys.argv[1:3]]
    verify(root, evidence, sys.argv[3])
