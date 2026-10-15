"""Read actual approved model results without authorizing or launching more work."""
import json
import sys
from pathlib import Path

from live_application_case import FIXTURE, source_hashes
from secret_settings import ledger, save

CAMPAIGN = "live-application-scans-20261015"


def verify(root, evidence, stage):
    assert root == FIXTURE / "target"
    control = FIXTURE / "approved-20261015"
    if stage == "initial":
        previous = json.loads((root / ".kuzushi/reports/findings.json").read_text())
        assert previous["metadata"]["investigation"]["campaignId"] == CAMPAIGN
        save(evidence, "prior-native-export", previous)
    assert source_hashes(root) == json.loads((FIXTURE / "control/source-before.json").read_text())
    assert json.loads((root / ".kuzushi/threat-models/manifest.json").read_text()).get("active") is None
    plan = json.loads((root / ".kuzushi/v3/campaigns" / CAMPAIGN / "plan.json").read_text())
    queue = json.loads((root / ".kuzushi/v3/campaigns" / CAMPAIGN / "queue.json").read_text())["jobs"]
    assert len(plan["jobs"]) == len(queue) == 3 and plan["workers"] == 1
    assert all(job["state"] == "completed" and job["attempts"] == 1 for job in queue.values())
    assert len({job["runId"] for job in queue.values()}) == 3
    with ledger(root, evidence) as db:
        rows = db.execute("select call_json,settled_at,review from investigation_call_reservations").fetchall()
        assert len(rows) == 3 and all(settled is not None and review == 0 for _, settled, review in rows)
        calls = [json.loads(row[0]) for row in rows]
        assert all(call["model"] == "openai-codex:gpt-6-luna" for call in calls)
        assert len({call["runId"] for call in calls}) == 3
        assert db.execute("select count(*) from finding_observations").fetchone()[0] == 3
        assert db.execute("select count(*) from investigation_work_attempts").fetchone()[0] == 3
        assert db.execute("select count(*) from review_decisions").fetchone()[0] == 0
        approval = json.loads(db.execute("select approval_json from investigation_allowance_revisions order by revision desc limit 1").fetchone()[0])
        assert approval["limits"] == {"maxProviderCalls": 8, "protectedReviewCalls": 2}
        assert approval["workPlan"]["campaignId"] == CAMPAIGN
    occurrence = json.loads((control / "controller-v2.stdout.json").read_text())
    assert (occurrence["planned"], occurrence["completed"], occurrence["failed"]) == (3, 3, 0)
    assert len(occurrence["rows"]) == 1 and occurrence["rows"][0]["seen"] == 3
    assert len(occurrence["rows"][0]["fingerprints"]) == 3
    if stage in ["exported", "restarted"]:
        report = json.loads((root / ".kuzushi/reports/findings.json").read_text())
        receipt = report["metadata"]["investigation"]
        assert receipt["campaignId"] == CAMPAIGN and receipt["observationCount"] == 3
        assert receipt["reviewedCount"] == receipt["confirmedCount"] == 0
        assert receipt["occurrence"]["rows"][0]["seen"] == 3
        accounting = receipt["allowance"]["currentInvestigation"]
        assert accounting["committedCalls"] == 3 and accounting["unresolvedCalls"] == 0
        assert accounting["reviewCalls"] == 0 and accounting["limits"]["protectedReviewCalls"] == 2
    save(evidence, stage + "-verified", {"fixedJobs": 3, "completedJobs": 3, "providerRequests": 3,
        "cumulativeExperimentRequests": 11, "authorizedExperimentMaximum": 14, "observations": 3,
        "identityGroups": 1, "protectedReviewCalls": 2, "reviewWorkStarted": False,
        "sourceUnchanged": True, "sourceExecuted": False, "helperProductDispatches": 0})


if __name__ == "__main__":
    root, evidence = [Path(p).resolve() for p in sys.argv[1:3]]
    verify(root, evidence, sys.argv[3])
