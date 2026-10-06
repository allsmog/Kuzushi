"""Offline directory scope fixture and finite draft assertions. No providers."""
import json
import sqlite3
import sys
from pathlib import Path


def seed(root):
    for name in ("service", "other"):
        (root / name).mkdir(exist_ok=True)
        (root / name / "app.py").write_text("print('scope fixture')\n")


def verify(root, evidence, drafts):
    plans = list((root / ".kuzushi/v3/campaigns").glob("*/plan.json"))
    assert len(plans) == drafts, f"expected {drafts} draft plans, found {len(plans)}"
    for path in (root / ".kuzushi/v3/runs").glob("*/*.json"):
        assert json.loads(path.read_text()).get("tool") != "sast:scan", "scanner work was admitted"
    for path in plans:
        plan = json.loads(path.read_text())
        assert plan["requiresWorkApproval"] is True
        assert plan["trialsPlanned"] == len(plan["jobs"]) == 3
        assert plan["effectiveWorkers"] == 1
        assert plan["baseInput"]["paths"] == ["service"]
        assert plan["baseInput"]["tasks"] == ["secret-scan"]
        assert all(job["input"]["paths"] == ["service"] for job in plan["jobs"])
    db = root / ".kuzushi/v3/index.sqlite3"
    with sqlite3.connect(db.as_uri() + "?mode=ro", uri=True) as connection:
        tables = {row[0] for row in connection.execute("select name from sqlite_master where type='table'")}
        for table in ("investigation_work_attempts", "investigation_call_reservations"):
            if table in tables:
                assert connection.execute(f"select count(*) from {table}").fetchone()[0] == 0
    (evidence / f"scope-drafts-{drafts}.json").write_text(json.dumps({
        "drafts": drafts, "approvedPlans": 0, "scanJobsStarted": 0,
        "liveProviderCalls": 0, "selectedPaths": ["service"] if drafts else None,
    }, indent=2) + "\n")


if __name__ == "__main__":
    root, evidence, action = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if action == "seed":
        seed(root)
    elif action == "blocked":
        verify(root, evidence, 0)
    elif action == "draft":
        verify(root, evidence, 1)
    else:
        raise ValueError(action)
