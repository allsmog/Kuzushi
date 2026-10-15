"""Read the completed approved source-input Review without starting more work."""
import hashlib
import json
import sqlite3
import sys
from pathlib import Path

from live_application_case import FIXTURE, OWNER, source_hashes
from secret_settings import ledger, save

CAMPAIGN = "live-application-source-review-20261015"
MODEL = "openai-codex:gpt-6-luna"


def discovery_and_prior_decision_unchanged(db):
    path = FIXTURE / "review-proposed-20261015/checkpointed-ledger.sqlite3"
    with sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True) as prior:
        columns = [r[1] for r in db.execute("pragma table_info(finding_observations)")]
        old = {r[0]: r for r in prior.execute("select * from finding_observations")}
        current = {r[0]: r for r in db.execute("select * from finding_observations")}
        assert old.keys() == current.keys() and len(old) == 3
        for identity, previous in old.items():
            for column, before, after in zip(columns, previous, current[identity]):
                if column == "finding_json":
                    before, after = json.loads(before), json.loads(after)
                    before.pop("triage", None)
                    after.pop("triage", None)
                assert before == after, column
        # finding_json.triage is a mutable projection. Durable decisions retain history.
        old_decisions = set(prior.execute("select * from review_decisions"))
        assert len(old_decisions) == 1
        assert old_decisions <= set(db.execute("select * from review_decisions"))


def verify(root, evidence, stage):
    assert root == FIXTURE / "target"
    control = FIXTURE / "source-review-proposed-20261015"
    before = json.loads((control / "before.json").read_text())
    original = json.loads((FIXTURE / "review-proposed-20261015/before.json").read_text())
    assert source_hashes(root) == before["source"]
    manifest = root / ".kuzushi/threat-models/manifest.json"
    assert hashlib.sha256(manifest.read_bytes()).hexdigest() == original["contextManifestSha256"]
    assert json.loads(manifest.read_text()).get("active") is None
    assert hashlib.sha256((OWNER / ".kuzushi/v3/config.toml").read_bytes()).hexdigest() == original["operatorConfigSha256"]
    assert hashlib.sha256((FIXTURE / "home/.kuzushi/v3/config.toml").read_bytes()).hexdigest() == before["configSha256"]
    campaign = root / ".kuzushi/v3/campaigns" / CAMPAIGN
    plan = json.loads((campaign / "plan.json").read_text())
    queue = json.loads((campaign / "queue.json").read_text())["jobs"]
    assert plan["workers"] == len(plan["jobs"]) == len(queue) == 1
    job = queue["review-001"]
    assert job["state"] == "completed" and job["attempts"] == job["dispatches"] == 1
    run = root / ".kuzushi/v3/runs" / job["runId"]
    result = json.loads((run / "result.json").read_text())
    data = result["data"]
    assert result["status"] == "completed" and data["attempted"] == data["successful"] == data["needsReview"] == 1
    assert data["failed"] == data["persistenceFailures"] == data["unappliedOpinions"] == 0
    opinion = data["results"][0]
    assert opinion["verdict"] == "needs_review" and abs(opinion["confidence"] - 0.6) < 0.000001
    assert opinion["cached"] is False and opinion["decisionApplied"] is True
    assert "not provided" in opinion["rationale"] and "downstream" in opinion["rationale"]
    model = next(r for r in data["stages"] if r.get("stageKind") == "model-review")
    dedupe = next(r for r in data["stages"] if r["stage"] == "dedupe")
    assert model["model"] == MODEL and model["providerSpendUnresolved"] is True
    assert "costUsd" not in model and "observedCostUsd" not in dedupe
    calls = json.loads((run / "run.json").read_text())["llmCalls"]
    assert len(calls) == 1 and calls[0]["model"] == MODEL and calls[0]["callAttempted"]
    draft = json.loads((control / "review-draft.stdout.json").read_text())["data"]
    assert plan["jobs"][0]["input"] == draft["input"]
    source = draft["sourceEvidence"]
    assert source["includedBytes"] == 432 and len(source["observations"]) == 1
    assert source["observations"][0]["text"] == (root / "services/gateway/routes.py").read_text()
    with ledger(root, evidence) as db:
        reservations = db.execute("select call_json,settled_at,review from investigation_call_reservations").fetchall()
        assert len(reservations) == 5 and all(r[1] is not None for r in reservations)
        assert sum(r[2] for r in reservations) == 2
        assert all(json.loads(r[0])["model"] == MODEL for r in reservations)
        assert db.execute("select count(*) from investigation_work_attempts").fetchone()[0] == 5
        assert db.execute("select count(*) from review_decisions").fetchone()[0] == 2
        assert db.execute("select count(*) from review_decisions where author='auto'").fetchone()[0] == 2
        approval = json.loads(db.execute("select approval_json from investigation_allowance_revisions order by revision desc limit 1").fetchone()[0])
        assert approval["limits"] == {"maxProviderCalls": 5, "protectedReviewCalls": 2}
        assert approval["workPlan"]["campaignId"] == CAMPAIGN
        discovery_and_prior_decision_unchanged(db)
    if stage in ["exported", "restarted"]:
        report = json.loads((root / ".kuzushi/reports/findings.json").read_text())
        finding = report["findings"][0]
        assert report["count"] == 1 and finding["reviewDecision"] == "needs_review"
        assert finding["reviewDecisionAuthor"] == "auto" and abs(finding["confidence"] - 0.6) < 0.000001
        investigation = report["metadata"]["investigation"]
        assert investigation["observationCount"] == 3
        assert investigation["reviewedCount"] == investigation["confirmedCount"] == 0
        assert investigation["occurrence"]["rows"][0]["seen"] == 3
        accounting = investigation["allowance"]["currentInvestigation"]
        assert accounting["committedCalls"] == 5 and accounting["reviewCalls"] == 2
        assert accounting["unresolvedCalls"] == 0 and accounting["cost"]["observedUsd"] is None
    save(evidence, stage + "-verified", {"completedSourceReviewJobs": 1,
        "newActualRequests": 1, "cumulativeExperimentRequests": 13,
        "investigationCalls": 5, "reviewCalls": 2, "unresolvedReservations": 0,
        "discoveryObservations": 3, "originalDiscoveryFieldsUnchanged": True,
        "priorDecisionRetained": True, "automaticDecisions": 2, "humanDecisions": 0,
        "dollars": "unknown", "sourceUnchanged": True, "sourceExecuted": False,
        "helperProductDispatches": 0})


if __name__ == "__main__":
    root, evidence = [Path(p).resolve() for p in sys.argv[1:3]]
    verify(root, evidence, sys.argv[3])
