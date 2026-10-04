"""Check a first-session Map draft without executing its model-backed job."""
import json
import re
import sqlite3
import sys
from pathlib import Path


def verify(root, evidence, stage):
    paths = list((root / ".kuzushi/v3/campaigns").glob("*/plan.json"))
    assert len(paths) == 1, "Returning to Setup must reuse the same draft"
    plan = json.loads(paths[0].read_text())
    assert plan["kind"] == "context-study" and plan["requiresWorkApproval"]
    assert plan["workers"] == plan["requestedWorkers"] == plan["effectiveWorkers"] == 1
    assert [job["tool"] for job in plan["jobs"]] == [
        "context:build", "entry-points:extract", "threat-model:build"
    ]
    assert [job["jobId"] for job in plan["jobs"]] == ["prepare-001", "prepare-002", "context-001"]
    context = plan["jobs"][-1]["input"]
    assert context["activate"] is False and context["newModel"] is True
    assert context["pipeline"] == "single" and context["variantScan"] is False
    assert context["sources"] == ["source-code"]
    assert context["model"] == "openai-codex:gpt-5.5"
    assert not (root / ".kuzushi/threat-models/manifest.json").exists()
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=ro", uri=True) as connection:
        tables = {row[0] for row in connection.execute("select name from sqlite_master where type='table'")}
        for table in ["investigation_work_attempts", "investigation_call_reservations"]:
            if table in tables:
                assert connection.execute("select count(*) from " + table).fetchone()[0] == 0, table
        if stage in ("approved", "resumed"):
            rows = list(connection.execute("select approval_json from investigation_allowance_revisions where investigation_id=?", (plan["investigationId"],)))
            assert len(rows) == 1, "Navigation must not create another allowance"
            approval = json.loads(rows[0][0])
            assert approval["limits"] == {"maxProviderCalls": 5, "protectedReviewCalls": 2}
            assert len(approval["workPlan"]["jobs"]) == 3
            assert all(job["maxAttempts"] == 1 for job in approval["workPlan"]["jobs"])
    if stage == "resumed":
        ansi = next(evidence.glob("*-recovered-map.ansi")).read_text()
        sgr = re.findall(r"\x1b\[([0-9;:]*)m", ansi)
        for codes in sgr:
            values = {int(code) for code in re.split("[;:]", codes) if code}
            assert not values.intersection(set(range(30, 39)) | set(range(40, 49)) | set(range(90, 98)) | set(range(100, 108))), "NO_COLOR capture contains color SGR"
    (evidence / "resume-command.txt").write_text("campaign " + plan["campaignId"])
    (evidence / (stage + "-check.json")).write_text(json.dumps({
        "campaignId": plan["campaignId"], "investigationId": plan["investigationId"],
        "jobCount": 3, "jobsStarted": 0, "providerCalls": 0,
    }, indent=2) + "\n")


if __name__ == "__main__":
    verify(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3])
