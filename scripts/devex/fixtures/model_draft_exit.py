"""Question-draft navigation on owned source. Never launches model work."""
import hashlib
import json
import sys
from pathlib import Path

import context_question
from secret_settings import ledger


def inspect(root, evidence, stage):
    source = hashlib.sha256((root / "app.py").read_bytes()).hexdigest()
    assert source == (evidence / "source-before.sha256").read_text()
    context = hashlib.sha256((root / ".kuzushi/threat-models/manifest.json").read_bytes()).hexdigest()
    assert context == json.loads((evidence / "context-manifest-before.json").read_text())["sha256"]
    calls = evidence / "synthetic-provider-calls.jsonl"
    assert not calls.exists() or not calls.read_text().strip()
    plans = list((root / ".kuzushi/v3/campaigns").glob("*/plan.json"))
    if stage == "unprepared":
        assert not plans
    else:
        plan = context_question.question_plan(root)
        frozen = plan["jobs"][0]["input"]
        assert frozen["question"] == "Explain the two entry points in this accepted context.\nKeep uncertainty explicit, including β."
        assert frozen["threatModelRef"] == json.loads((evidence / "map-ref.json").read_text())
        assert plan["workers"] == 1 and len(plan["jobs"]) == 1
        assert not (root / ".kuzushi/v3/campaigns" / plan["campaignId"] / "queue.json").exists()
    with ledger(root, evidence) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        for table in ["investigation_call_reservations", "investigation_work_attempts", "finding_observations", "finding_decisions", "review_decisions"]:
            if table in tables:
                assert db.execute("select count(*) from " + table).fetchone()[0] == 0, table
    context_question.save(evidence, stage + "-exit-check", {
        "liveProviderCalls": 0, "syntheticProviderCalls": 0, "sourceExecuted": False,
        "contextUnchanged": True, "findingDecisionsChanged": False,
        "plans": len(plans), "jobsStarted": 0})


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    evidence.mkdir(parents=True, exist_ok=True)
    if stage == "seed":
        context_question.seed(root, evidence, Path(sys.argv[4]).resolve())
    else:
        inspect(root, evidence, stage)
