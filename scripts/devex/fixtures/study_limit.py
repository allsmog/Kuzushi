"""An approved finite study stops before consuming its protected review calls."""
import json
import os
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True
import study_execution


def verify_stopped(root, evidence):
    plan = study_execution.verify_plan(root, evidence, "finished", allowance_calls=5,
                                       completed_calls=3, work_attempts=4)
    queue = json.loads((root / ".kuzushi/v3/campaigns" / plan["campaignId"] / "queue.json").read_text())
    jobs = list(queue["jobs"].values())
    assert len(jobs) == 3 and all(job["attempts"] == 1 for job in jobs)
    assert sorted(job["state"] for job in jobs) == ["completed", "completed", "failed"]
    calls = [json.loads(line) for line in (evidence / "provider-calls.jsonl").read_text().splitlines()]
    assert len(calls) == 2 and len({call["bridgePid"] for call in calls}) == 2
    assert all(call["hasGeneratedContext"] for call in calls)
    report = study_execution.query(os.environ["KUZUSHI_NATIVE_BIN"], root,
                                   ["findings", "batch", plan["campaignId"]])
    assert (report["completed"], report["planned"], report["failed"], report["pending"]) == (2, 3, 1, 0)
    assert len(report["rows"]) == 1 and report["rows"][0]["seen"] == 2
    (evidence / "open-recurring.txt").write_text("open " + report["rows"][0]["representativeFingerprint"])
    (evidence / "limit-receipt.json").write_text(json.dumps({
        "plannedJobs": 3, "completedJobs": 2, "failedJobs": 1, "discoveryCalls": 2,
        "contextCalls": 1, "totalAllowance": 5, "protectedReviewCalls": 2,
        "queueCompletionInjected": False, "liveProviderCalls": 0, "findingsAreSynthetic": True,
    }, indent=2) + "\n")


def verify_selection(root, evidence, selected):
    events = [json.loads(line) for line in (root / ".kuzushi/v3/workflow/phase-attempts.jsonl").read_text().splitlines()]
    scans = [event for event in events if event["event"] == "phase_attempt_completed" and event["phase"] == "scan"]
    assert len(scans) == 1 and scans[0]["outcome"] == "partial"
    dispositions = [event for event in events if event["event"] == "phase_attempt_disposition_recorded"
                    and event["attemptId"] == scans[0]["attemptId"]]
    if selected:
        assert len(dispositions) == 1 and dispositions[0]["disposition"] == {
            "kind": "selected", "acknowledged_partial": True,
        }
    else:
        assert not dispositions, "Finishing partial work must not implicitly accept it"
    verify_stopped(root, evidence)


def verify_report(root, evidence):
    report = json.loads((root / ".kuzushi/reports/findings.json").read_text())
    assert report["count"] == 1
    row = json.dumps(report["findings"][0])
    assert "false_positive" in row and "Labeled synthetic limit observation" in row
    verify_selection(root, evidence, True)


if __name__ == "__main__":
    root, evidence, action = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if action == "seed":
        study_execution.seed(root, evidence, Path(sys.argv[4]).resolve())
    elif action == "stopped":
        deadline = time.monotonic() + 60
        while True:
            try:
                verify_stopped(root, evidence)
                break
            except (AssertionError, FileNotFoundError):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.25)
    elif action == "unselected":
        verify_selection(root, evidence, False)
    elif action == "selected":
        verify_selection(root, evidence, True)
    elif action == "report":
        verify_report(root, evidence)
    else:
        study_execution.verify_plan(root, evidence, action, allowance_calls=5)
