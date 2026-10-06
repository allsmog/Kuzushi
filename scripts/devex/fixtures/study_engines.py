"""Study-local engine selection over accepted source. No discovery executes."""
import json
import sqlite3
import sys
from pathlib import Path
import exact_scope


def verify(root, evidence, stage):
    state = root / ".kuzushi/v3"
    plans = [json.loads(path.read_text()) for path in (state / "campaigns").glob("*/plan.json")]
    if stage == "picker":
        assert not plans
    else:
        assert len(plans) == 1
        plan = plans[0]
        assert plan["baseInput"]["tasks"] == ["secret-scan"]
        assert plan["baseInput"]["scanScopeRef"] == json.loads((evidence / "scope-reference.json").read_text())
        assert len(plan["jobs"]) == 3 and plan["workers"] == 1
        assert not (state / "campaigns" / plan["campaignId"] / "queue.json").exists()
        (evidence / "resume-command.txt").write_text(f"campaign {plan['campaignId']}")
        if stage == "draft":
            (evidence / "saved-plan.json").write_text(json.dumps(plan, sort_keys=True))
        elif stage == "restarted":
            assert plan == json.loads((evidence / "saved-plan.json").read_text()), "Engine inspection must preserve the exact saved plan"
    for path in (state / "runs").glob("*/run.json"):
        assert json.loads(path.read_text()).get("tool") != "sast:scan", "No discovery is authorized by this journey"
    with sqlite3.connect((state / "index.sqlite3").as_uri() + "?mode=ro", uri=True) as connection:
        tables = {row[0] for row in connection.execute("select name from sqlite_master where type='table'")}
        for table in ("investigation_call_reservations", "investigation_work_attempts"):
            if table in tables:
                assert connection.execute(f"select count(*) from {table}").fetchone()[0] == 0
    (evidence / f"engines-{stage}.json").write_text(json.dumps({"stage": stage, "plannedStudies": len(plans), "scanJobsStarted": 0, "providerCalls": 0, "nativeEngine": "secret-scan" if plans else None}, indent=2) + "\n")


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "seed":
        exact_scope.seed(root, evidence)
        (evidence / "ignored-paste.txt").write_text("this must not replace the composer\nsecond line")
    else:
        verify(root, evidence, stage)
