"""Seed and inspect immutable study contexts through real offline tool dispatch."""
import json
import os
import sqlite3
import sys
from pathlib import Path
from context_comparison import import_context


def seed(root, evidence):
    evidence.mkdir(parents=True, exist_ok=True)
    binary = os.environ["KUZUSHI_NATIVE_BIN"]
    first = import_context(binary, root, evidence, "alpha")
    active = import_context(binary, root, evidence, "beta")
    (evidence / "context-refs.json").write_text(json.dumps({"selected": first, "active": active}, indent=2))


def verify(root, evidence, omitted):
    refs = json.loads((evidence / "context-refs.json").read_text())
    manifest = json.loads((root / ".kuzushi/threat-models/manifest.json").read_text())
    assert manifest["active"] == refs["active"], "Study selection must not activate another context"
    plans = [json.loads(path.read_text()) for path in (root / ".kuzushi/v3/campaigns").glob("*/plan.json")]
    assert len(plans) == (2 if omitted else 1), "Exactly one new finite draft per explicit preparation"
    assert all(plan["trialsPlanned"] == 3 for plan in plans)
    assert all(plan["baseInput"]["tasks"] == ["secret-scan"] for plan in plans)
    contexts = [plan["baseInput"]["threatModelRef"] for plan in plans]
    assert refs["selected"] in contexts
    selected_plan = next(plan for plan in plans if plan["baseInput"]["threatModelRef"] == refs["selected"])
    (evidence / "resume-command.txt").write_text("campaign " + selected_plan["campaignId"])
    assert (None in contexts) == omitted
    assert len({plan["investigationId"] for plan in plans}) == 1, "Context revisions must retain investigation accounting"
    db = root / ".kuzushi/v3/index.sqlite3"
    with sqlite3.connect(db.as_uri() + "?mode=ro", uri=True) as connection:
        tables = {row[0] for row in connection.execute("select name from sqlite_master where type='table'")}
        for table in ["investigation_work_attempts", "investigation_call_reservations"]:
            if table in tables:
                assert connection.execute("select count(*) from " + table).fetchone()[0] == 0
    receipt = {"plans": len(plans), "contexts": contexts, "active": manifest["active"], "jobsStarted": 0, "providerCalls": 0}
    (evidence / ("omitted-check.json" if omitted else "selected-check.json")).write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    root, evidence, action = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if action == "seed":
        seed(root, evidence)
    else:
        verify(root, evidence, action == "omitted")
