"""Inspect context-study approval artifacts without starting a provider or job."""
import json
import sqlite3
import sys
from pathlib import Path


def verify(root, evidence, stage):
    paths = list((root / ".kuzushi/v3/campaigns").glob("*/plan.json"))
    assert len(paths) == 1, "Exactly one explicitly prepared context study"
    plan = json.loads(paths[0].read_text())
    assert plan["kind"] == "context-study" and plan["requiresWorkApproval"]
    assert plan["workers"] == plan["effectiveWorkers"] == 1
    assert len(plan["jobs"]) == 1
    job = plan["jobs"][0]
    assert job["tool"] == "threat-model:build"
    for key, expected in {"activate": False, "newModel": True, "seedMode": "fresh", "pipeline": "single", "sources": ["source-code"], "variantScan": False}.items():
        assert job["input"][key] == expected, key
    refs = json.loads((evidence / "context-refs.json").read_text())
    manifest = json.loads((root / ".kuzushi/threat-models/manifest.json").read_text())
    assert manifest["active"] == refs["active"], "Planning must preserve active context"
    db = root / ".kuzushi/v3/index.sqlite3"
    with sqlite3.connect(db.as_uri() + "?mode=ro", uri=True) as connection:
        tables = {row[0] for row in connection.execute("select name from sqlite_master where type='table'")}
        for table in ["investigation_work_attempts", "investigation_call_reservations"]:
            if table in tables:
                assert connection.execute("select count(*) from " + table).fetchone()[0] == 0, table
        if stage == "approved":
            row = connection.execute("select approval_json from investigation_allowance_revisions where investigation_id = ? order by revision desc limit 1", (plan["investigationId"],)).fetchone()
            approval = json.loads(row[0])
            assert approval["limits"] == {"maxProviderCalls": 5, "protectedReviewCalls": 2}
            assert approval["workPlan"]["campaignId"] == plan["campaignId"]
            assert len(approval["workPlan"]["jobs"]) == 1
            assert approval["workPlan"]["jobs"][0]["maxAttempts"] == 1
    (evidence / "resume-command.txt").write_text("campaign " + plan["campaignId"])
    receipt = {"stage": stage, "campaignId": plan["campaignId"], "investigationId": plan["investigationId"], "providerCalls": 0, "jobsStarted": 0, "activeContextPreserved": True}
    (evidence / (stage + "-check.json")).write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    verify(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3])
