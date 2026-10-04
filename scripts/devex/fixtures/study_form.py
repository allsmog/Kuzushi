"""Inspect the real study form's persisted artifacts; never calls a model."""
import json
import sqlite3
import sys
import time
from pathlib import Path


def verify(root, output, stage):
    paths = list((root / ".kuzushi/v3/campaigns").glob("*/plan.json"))
    assert len(paths) == 1, "The form must prepare exactly one immutable plan"
    plan = json.loads(paths[0].read_text())
    assert plan["requiresWorkApproval"] is True
    assert plan["trialsPlanned"] == len(plan["jobs"]) == 3
    assert plan["workers"] == 1
    assert plan["baseInput"]["tasks"] == ["secret-scan"]
    assert all(plan["baseInput"][key] is False for key in ["triage", "verify", "autoPatch"])
    assert plan["investigationId"]
    output.parent.joinpath("resume-command.txt").write_text("campaign " + plan["campaignId"])
    receipt = {"stage": stage, "campaignId": plan["campaignId"], "investigationId": plan["investigationId"], "jobs": 3}
    if stage != "draft":
        receipt.update(verify_allowance(root, plan, stage))
    output.write_text(json.dumps(receipt, indent=2) + "\n")


def verify_allowance(root, plan, stage):
    db = root / ".kuzushi/v3/index.sqlite3"
    with sqlite3.connect(db.as_uri() + "?mode=ro", uri=True) as connection:
        row = connection.execute("select approval_json from investigation_allowance_revisions where investigation_id = ? order by revision desc limit 1", (plan["investigationId"],)).fetchone()
        approval = json.loads(row[0])
        assert approval["limits"] == {"maxProviderCalls": 9, "protectedReviewCalls": 3}
        assert approval["workPlan"]["campaignId"] == plan["campaignId"]
        attempts = connection.execute("select count(*) from investigation_work_attempts").fetchone()[0]
        provider_calls = connection.execute("select count(*) from investigation_call_reservations").fetchone()[0]
        assert provider_calls == 0, "Offline journey must never admit provider transport"
        expected = 3 if stage == "finished" else 0
        assert attempts == expected, f"Expected {expected} starts, got {attempts}"
    if stage == "finished":
        queue = json.loads((root / ".kuzushi/v3/campaigns" / plan["campaignId"] / "queue.json").read_text())
        assert all(job["state"] == "completed" for job in queue["jobs"].values()), queue
    return {"jobAttempts": attempts, "providerCalls": provider_calls, "limits": approval["limits"]}


if __name__ == "__main__":
    root, output, stage = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
    deadline = time.monotonic() + (45 if stage == "finished" else 0)
    while True:
        try:
            verify(root, output, stage)
            break
        except (AssertionError, FileNotFoundError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.25)
