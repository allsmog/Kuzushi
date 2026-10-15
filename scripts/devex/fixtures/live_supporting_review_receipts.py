"""Inspect one completed, approved supporting-code Review without new work."""
import hashlib
import json
import sqlite3
import sys
from pathlib import Path

from live_application_case import FIXTURE, OWNER, source_hashes
from secret_settings import ledger, save

CAMPAIGN = "live-application-supporting-review-20261015"
MODEL = "openai-codex:gpt-6-luna"
CONTROL = FIXTURE / "supporting-review-proposed-20261015"


def unchanged_inputs(root):
    before = json.loads((CONTROL / "before.json").read_text())
    assert source_hashes(root) == before["source"]
    paths = [(FIXTURE / "home/.kuzushi/v3/config.toml", "configSha256"),
             (OWNER / ".kuzushi/v3/config.toml", "operatorConfigSha256"),
             (root / ".kuzushi/threat-models/manifest.json", "contextManifestSha256")]
    for path, key in paths:
        assert hashlib.sha256(path.read_bytes()).hexdigest() == before[key], key
    assert json.loads(paths[-1][0].read_text()).get("active") is None


def unchanged_discovery_and_prior_decisions(db):
    path = CONTROL / "before/checkpointed-ledger.sqlite3"
    with sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True) as prior:
        columns = [row[1] for row in db.execute("pragma table_info(finding_observations)")]
        old = {row[0]: row for row in prior.execute("select * from finding_observations")}
        current = {row[0]: row for row in db.execute("select * from finding_observations")}
        assert old.keys() == current.keys() and len(old) == 3
        for identity, previous in old.items():
            for column, before, after in zip(columns, previous, current[identity]):
                if column == "finding_json":
                    before, after = json.loads(before), json.loads(after)
                    before.pop("triage", None)
                    after.pop("triage", None)
                assert before == after, column
        decisions = set(prior.execute("select * from review_decisions"))
        assert len(decisions) == 2
        assert decisions <= set(db.execute("select * from review_decisions"))


def completed_job(root):
    campaign = root / ".kuzushi/v3/campaigns" / CAMPAIGN
    plan = json.loads((campaign / "plan.json").read_text())
    queue = json.loads((campaign / "queue.json").read_text())["jobs"]
    assert plan["workers"] == len(plan["jobs"]) == len(queue) == 1
    job = queue["review-001"]
    assert job["state"] == "completed" and job["attempts"] == job["dispatches"] == 1
    draft = json.loads((CONTROL / "review-draft.stdout.json").read_text())["data"]
    assert plan["jobs"][0]["input"] == draft["input"]
    source = draft["sourceEvidence"]
    assert source["schemaVersion"] == 2 and source["includedBytes"] == 3336
    observation = source["observations"][0]
    assert len(source["observations"]) == 1 and len(observation["supportingFiles"]) == 8
    assert observation["text"] == (root / "services/gateway/routes.py").read_text()
    for item in observation["supportingFiles"]:
        assert item["file"]["state"] == "captured"
        assert item["text"] == (root / item["file"]["path"]).read_text()
    return root / ".kuzushi/v3/runs" / job["runId"], draft


def actual_request_and_opinion(run):
    result = json.loads((run / "result.json").read_text())
    data = result["data"]
    assert result["status"] == "completed"
    assert data["attempted"] == data["successful"] == data["tp"] == 1
    assert data["failed"] == data["persistenceFailures"] == data["unappliedOpinions"] == 0
    opinion = data["results"][0]
    assert opinion["verdict"] == "true_positive" and abs(opinion["confidence"] - 0.85) < 0.000001
    assert opinion["cached"] is False and opinion["decisionApplied"] is True
    assert "not deployed exposure" in opinion["rationale"]
    calls = json.loads((run / "run.json").read_text())["llmCalls"]
    assert len(calls) == 1 and calls[0]["model"] == MODEL and calls[0]["callAttempted"]
    assert data["providerSpendUnresolved"] is True and calls[0]["providerSpendUnresolved"] is True
    return opinion


def accounting(root, evidence, draft):
    with ledger(root, evidence) as db:
        calls = db.execute("select call_json,settled_at,review from investigation_call_reservations").fetchall()
        assert len(calls) == 6 and all(row[1] is not None for row in calls)
        assert sum(row[2] for row in calls) == 3
        assert all(json.loads(row[0])["model"] == MODEL for row in calls)
        assert db.execute("select count(*) from investigation_work_attempts").fetchone()[0] == 6
        assert db.execute("select count(*) from review_decisions").fetchone()[0] == 3
        assert db.execute("select count(*) from review_decisions where author='auto'").fetchone()[0] == 3
        revision, raw = db.execute("select revision,approval_json from investigation_allowance_revisions order by revision desc limit 1").fetchone()
        approval = json.loads(raw)
        assert revision == 4 and approval["limits"] == {"maxProviderCalls": 6, "protectedReviewCalls": 3}
        assert approval["workPlan"]["campaignId"] == CAMPAIGN
        assert approval["workPlan"]["planSha256"] == draft["planSha256"]
        unchanged_discovery_and_prior_decisions(db)


def exported_report(root, opinion):
    report = json.loads((root / ".kuzushi/reports/findings.json").read_text())
    finding = report["findings"][0]
    assert report["count"] == 1 and finding["reviewDecision"] == "confirmed"
    assert finding["reviewDecisionAuthor"] == "auto"
    assert abs(finding["confidence"] - opinion["confidence"]) < 0.000001
    investigation = report["metadata"]["investigation"]
    assert investigation["observationCount"] == 3
    # These compatibility totals include automatic terminal decisions.
    # The independent ledger check above proves that no human decided this case.
    assert investigation["reviewedCount"] == investigation["confirmedCount"] == 1
    assert investigation["occurrence"]["rows"][0]["seen"] == 3
    allowance = investigation["allowance"]["currentInvestigation"]
    assert allowance["committedCalls"] == 6 and allowance["reviewCalls"] == 3
    assert allowance["unresolvedCalls"] == 0 and allowance["cost"]["observedUsd"] is None


def verify(root, evidence, stage):
    assert root == FIXTURE / "target"
    unchanged_inputs(root)
    run, draft = completed_job(root)
    opinion = actual_request_and_opinion(run)
    accounting(root, evidence, draft)
    if stage in ["exported", "restarted"]:
        exported_report(root, opinion)
    save(evidence, stage + "-verified", {"completedSupportingReviewJobs": 1,
        "newActualRequests": 1, "cumulativeExperimentRequests": 14,
        "investigationCalls": 6, "reviewCalls": 3, "unresolvedReservations": 0,
        "discoveryObservations": 3, "originalDiscoveryFieldsUnchanged": True,
        "priorDecisionsRetained": 2, "automaticDecisions": 3, "humanDecisions": 0,
        "sourceBytes": 3336, "supportingFiles": 8, "model": MODEL,
        "verdict": opinion["verdict"], "confidence": opinion["confidence"],
        "dollars": "unknown", "sourceUnchanged": True, "sourceExecuted": False,
        "helperProductDispatches": 0})


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    verify(root, evidence, sys.argv[3])
