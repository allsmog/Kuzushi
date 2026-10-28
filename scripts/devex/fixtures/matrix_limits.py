"""Finite matrix failure/retry and spending control with zero live inference."""
import hashlib
import json
import shutil
import sys
import time
from pathlib import Path

import context_matrix
from rejected_context import execute
from secret_settings import ledger

CAMPAIGN = "matrix-limits"
INVESTIGATION = "matrix-limits-accounting"


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def load(path):
    return json.loads(path.read_text())


def seed(root, evidence, home):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    context_matrix.seed(root, evidence, home)
    shutil.copyfile(Path(__file__).with_name("matrix_limits_provider.mjs"), evidence / "provider.mjs")
    refs = load(evidence / "before.json")["refs"]
    receipt = execute(root, home, evidence, "matrix-plan", "campaign:study", {
        "campaignId": CAMPAIGN, "investigationId": INVESTIGATION,
        "workers": 1, "trials": 3, "baselineCaseId": "alpha",
        "scanInput": {"taskMode": "manual", "tasks": ["agentic"]},
        "contextCases": [{"id": "alpha", "label": "Alpha baseline", "threatModelRef": refs["Alpha"]},
                         {"id": "beta", "label": "Beta candidate", "threatModelRef": refs["Beta"]}],
    })
    execute(root, home, evidence, "initial-offline-allowance", "campaign:approve-allowance", {
        "investigationId": INVESTIGATION, "expectedRevision": 0,
        "model": "openai-codex:gpt-5.5", "maxProviderCalls": 7, "protectedReviewCalls": 2,
        "reason": "Owned intercepted matrix: six fixed jobs, one attempt; preserve two Review calls",
        "campaignId": CAMPAIGN, "campaignPlanSha256": receipt["planSha256"],
        "campaignJobs": 6, "maxJobAttempts": 1,
    })
    plan = root / ".kuzushi/v3/campaigns" / CAMPAIGN / "plan.json"
    save(evidence, "plan-before", {"sha256": hashlib.sha256(plan.read_bytes()).hexdigest(),
                                  "jobIds": [job["jobId"] for job in load(plan)["jobs"]]})
    (evidence / "study-command.txt").write_text("campaign " + CAMPAIGN)


def state(root, evidence):
    path = root / ".kuzushi/v3/campaigns" / CAMPAIGN
    before = load(evidence / "before.json")
    assert context_matrix.source_digest(root) == before["sourceSha256"]
    assert load(root / ".kuzushi/threat-models/manifest.json")["active"] == before["refs"]["Gamma"]
    assert hashlib.sha256((root / ".kuzushi/threat-model.json").read_bytes()).hexdigest() == before["activeMirrorSha256"]
    original = load(evidence / "plan-before.json")
    assert hashlib.sha256((path / "plan.json").read_bytes()).hexdigest() == original["sha256"]
    queue = load(path / "queue.json")
    assert set(queue["jobs"]) == set(original["jobIds"]) and len(queue["jobs"]) == 6
    with ledger(root, evidence) as db:
        calls = db.execute("select count(*),sum(settled_at is null),sum(review) from investigation_call_reservations").fetchone()
        attempts = db.execute("select count(*) from investigation_work_attempts").fetchone()[0]
        observations = db.execute("select count(*) from finding_observations").fetchone()[0]
        decisions = db.execute("select count(*) from review_decisions").fetchone()[0]
        decision_records = db.execute("select id,finding_id,decision_verdict,rationale,author,decision_event_seq,decision_event_hash from review_decisions order by id").fetchall()
        approval = json.loads(db.execute("select approval_json from investigation_allowance_revisions order by revision desc limit 1").fetchone()[0])
    return {"queue": queue, "calls": calls, "attempts": attempts,
            "observations": observations, "decisions": decisions,
            "decisionRecords": decision_records, "approval": approval}


def verify_draft(root, evidence):
    before = load(evidence / "before.json")
    plan = load(root / ".kuzushi/v3/campaigns" / CAMPAIGN / "plan.json")
    assert plan["kind"] == "context-matrix" and plan["jobCount"] == 6 and plan["workers"] == 1
    assert plan["contextMatrix"]["baselineCaseId"] == "alpha"
    cases = plan["contextMatrix"]["cases"]
    assert [case["id"] for case in cases] == ["alpha", "beta"]
    assert [case["baseInput"]["threatModelRef"] for case in cases] == [before["refs"][name] for name in ["Alpha", "Beta"]]
    assert all(case["passes"] == 3 for case in cases)
    assert not context_matrix.calls(evidence)
    with ledger(root, evidence) as db:
        assert db.execute("select count(*) from investigation_call_reservations").fetchone()[0] == 0
        assert db.execute("select count(*) from investigation_work_attempts").fetchone()[0] == 0
        assert db.execute("select count(*) from finding_observations").fetchone()[0] == 0
    save(evidence, "draft-check", {"jobs": 6, "cases": 2, "workers": 1,
                                  "interceptedRequests": 0, "liveProviderRequests": 0})


def verify_case_review(root, evidence):
    current = state(root, evidence)
    assert current["calls"] == (5, 0, 0) and current["decisions"] == 0
    assert current["observations"] == 3
    with ledger(root, evidence) as db:
        original = json.loads(db.execute(
            "select finding_json from finding_observations order by created_seq limit 1").fetchone()[0])
        latest = json.loads(db.execute(
            "select finding_json from finding_observations order by created_seq desc limit 1").fetchone()[0])
    reference = "generation:" + str(original["id"])
    captures = sorted(evidence.glob("*-recorded-case-reference.txt"))
    assert len(captures) == 1
    displayed = captures[0].read_text()
    assert reference in displayed, (reference, displayed)
    assert "generation:" + str(latest["id"]) not in displayed
    save(evidence, "case-review-check", {
        "exactObservation": reference, "renderedObservationRef": reference,
        "originalRun": original["scan_id"], "interceptedRequests": 5,
        "decisionRecords": 0, "rawObservations": 3, "liveProviderRequests": 0})


def verify_case_report(root, evidence):
    current = state(root, evidence)
    assert current["calls"] == (5, 0, 0) and current["decisions"] == 0
    assert current["observations"] == 3
    captures = sorted(evidence.glob("*-review-scoped-report.txt"))
    assert len(captures) == 1
    displayed = captures[0].read_text()
    for expected in ["Scope: context matrix " + CAMPAIGN, "5 committed / 7 calls", "3 raw observations"]:
        assert expected in displayed, (expected, displayed)
    save(evidence, "case-report-check", {"campaignId": CAMPAIGN, "interceptedRequests": 5,
        "decisionRecords": 0, "rawObservations": 3, "liveProviderRequests": 0})


def wait_terminal(root, evidence, completed):
    directory = root / ".kuzushi/v3/campaigns" / CAMPAIGN
    for _ in range(40):
        queue = directory / "queue.json"
        events = directory / "events.jsonl"
        if queue.exists() and events.exists():
            rows = [json.loads(line) for line in events.read_text().splitlines()]
            jobs = load(queue)["jobs"].values()
            if rows and rows[-1]["event"] == "dispatch-end" and sum(job["state"] == "completed" for job in jobs) == completed:
                return
        time.sleep(1)
    raise AssertionError("The existing dispatcher did not publish the expected terminal state")


def verify(root, evidence, stage):
    assert stage in ["partial", "reviewed", "partial-report", "finished", "reaffirmed", "exported", "restarted"], stage
    finished = stage in ["finished", "reaffirmed", "exported", "restarted"]
    wait_terminal(root, evidence, 6 if finished else 4)
    current = state(root, evidence)
    expected = 7 if finished else 5
    calls = context_matrix.calls(evidence)
    assert len(calls) == current["calls"][0] == current["attempts"] == expected
    assert current["calls"][2] == 0
    assert sum(row["failed"] for row in calls) == 1
    assert current["observations"] == (4 if finished else 3)
    reaffirmed = stage in ["reaffirmed", "exported", "restarted"]
    assert current["decisions"] == (0 if stage == "partial" else 2 if reaffirmed else 1)
    if reaffirmed:
        original = load(evidence / "reviewed-state.json")["decisionRecords"][0]
        assert list(current["decisionRecords"][0]) == original
        assert current["decisionRecords"][1][3].startswith("J363 explicit reaffirmation")
    assert current["approval"]["limits"] == {"maxProviderCalls": 9 if finished else 7, "protectedReviewCalls": 2}
    counts = {name: sum(job["state"] == name for job in current["queue"]["jobs"].values())
              for name in ["completed", "failed", "parked"]}
    assert counts == ({"completed": 6, "failed": 0, "parked": 0} if finished else {"completed": 4, "failed": 1, "parked": 1}), counts
    if finished:
        assert sorted(len(job["attemptRuns"]) for job in current["queue"]["jobs"].values()) == [1, 1, 1, 1, 1, 2]
        partial = load(evidence / "partial-state.json")["queue"]["jobs"]
        for job_id, previous in partial.items():
            history = previous.get("attemptRuns", [])
            assert current["queue"]["jobs"][job_id]["attemptRuns"][:len(history)] == history
    for context in ["Alpha", "Beta"]:
        assert len({row["promptSha256"] for row in calls if row["context"] == context}) == 1
    save(evidence, stage + "-state", {**current, "interceptedRequests": expected,
                                    "liveProviderRequests": 0, "sourceExecuted": False})
    if stage in ["partial-report", "exported", "restarted"]:
        verify_report(root, evidence, stage, finished)


def verify_report(root, evidence, stage, finished):
    report = load(root / ".kuzushi/reports/findings.json")
    receipt = report["metadata"]["investigation"]
    assert receipt["kind"] == "context-matrix" and receipt["campaignId"] == CAMPAIGN
    assert receipt["observationCount"] == (4 if finished else 3)
    assert receipt["findingCount"] == receipt["reviewedCount"] == 1
    assert receipt["confirmedCount"] == 0
    assert len(receipt["attempts"]) == (7 if finished else 5)
    assert sum(attempt["scan"]["outcome"] == "failed" for attempt in receipt["attempts"]) == 1
    assert report["findings"][0]["reviewDecision"] == "rejected_false_positive"
    assert [case["id"] for case in receipt["occurrence"]["cases"]] == ["alpha", "beta"]
    for case, completed, seen in zip(receipt["occurrence"]["cases"], [3, 3] if finished else [2, 2], [3, 1] if finished else [2, 1]):
        assert case["occurrence"]["completed"] == completed
        assert case["occurrence"]["rows"][0]["seen"] == seen
    assert receipt["allowance"]["currentInvestigation"]["committedCalls"] == (7 if finished else 5)
    save(evidence, stage + "-report-check", {"rawObservations": receipt["observationCount"],
        "findingCount": 1, "humanDecisionPreserved": True, "cases": 2,
        "perCaseCompleted": [3, 3] if finished else [2, 2], "retainedFailedAttempts": 1,
        "totalAttempts": len(receipt["attempts"]), "providerRequests": 0})


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    elif stage == "draft":
        verify_draft(root, evidence)
    elif stage == "case-review":
        verify_case_review(root, evidence)
    elif stage == "case-report":
        verify_case_report(root, evidence)
    else:
        verify(root, evidence, stage)
