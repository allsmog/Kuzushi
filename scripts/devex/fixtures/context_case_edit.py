"""Installed native context cases over harmless owned policy text."""
import json
import sys
import time
from pathlib import Path

import bounded_semgrep
from secret_settings import ledger

LABELS = ["Baseline policy", "Owner context"]


def seed(root, evidence, home):
    bounded_semgrep.seed(root, evidence, home)
    (evidence / "candidate-context.txt").write_text("Owner context for harmless local-rule observations. Inspect both owned text files; do not execute source or infer vulnerability or fixed status.")
    (evidence / "invalid-name.txt").write_text("invalid\nname")


def selected_plan(root, evidence):
    plans = [json.loads(p.read_text()) for p in (root / ".kuzushi/v3/campaigns").glob("*/plan.json")]
    matrices = [p for p in plans if p.get("kind") == "context-matrix"]
    assert len(matrices) == 1
    plan = matrices[0]
    cases = plan["contextMatrix"]["cases"]
    assert [case["label"] for case in cases] == LABELS
    assert len(cases) == 2 and plan["jobCount"] == len(plan["jobs"]) == 6 and plan["workers"] == 1
    assert plan["contextMatrix"]["baselineCaseId"] == cases[0]["id"]
    assert all(case["passes"] == 3 for case in cases)
    assert cases[0]["baseInput"]["threatModelRef"] != cases[1]["baseInput"]["threatModelRef"]
    for case in cases:
        scan = case["baseInput"]
        assert scan["tasks"] == ["semgrep"] and scan["semgrepTimeoutMs"] == 60000
        assert case["equivalence"]["components"].get("model") is None
        assert all(not scan[key] for key in ["triage", "verify", "patch", "autoPatch", "pocExecution", "dynamicAnalysis"])
    (evidence / "resume-command.txt").write_text("campaign " + plan["campaignId"])
    return plan


def count_rows(root, evidence):
    with ledger(root, evidence) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        return {name: db.execute("select count(*) from " + name).fetchone()[0] if name in tables else None
                for name in ["finding_observations", "investigation_call_reservations", "investigation_work_attempts", "review_decisions"]}


def verify(root, evidence, stage):
    assert bounded_semgrep.source_hashes(root) == json.loads((evidence / "source-before.json").read_text())
    assert json.loads((root / ".kuzushi/threat-models/manifest.json").read_text()).get("active") is None
    plan = selected_plan(root, evidence)
    queue = root / ".kuzushi/v3/campaigns" / plan["campaignId"] / "queue.json"
    if stage == "draft":
        assert not queue.exists()
        assert all(value in [None, 0] for value in count_rows(root, evidence).values())
    else:
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if queue.exists() and all(job["state"] == "completed" for job in json.loads(queue.read_text())["jobs"].values()):
                break
            time.sleep(0.2)
        states = json.loads(queue.read_text())["jobs"]
        assert len(states) == 6 and all(job["state"] == "completed" and job["attempts"] == 1 for job in states.values())
        counts = count_rows(root, evidence)
        assert counts["finding_observations"] == counts["investigation_work_attempts"] == 6
        assert counts["investigation_call_reservations"] == 0
        for job in plan["jobs"]:
            run = states[job["jobId"]]["runId"]
            result = json.loads((root / ".kuzushi/v3/runs" / run / "result.json").read_text())
            assert result["status"] == "completed"
            findings = result["data"]["coreFindings"]
            assert len(findings) == 1 and findings[0]["file_path"].endswith("service/notice.py")
    (evidence / (stage + "-check.json")).write_text(json.dumps({"campaignId":plan["campaignId"], "cases":2,
        "jobs":6, "labels":LABELS, "providerCalls":0, "sourceExecuted":False, "globalContextUnchanged":True,
        "counts":count_rows(root,evidence)}, indent=2) + "\n")


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]))
    else:
        verify(root, evidence, stage)
