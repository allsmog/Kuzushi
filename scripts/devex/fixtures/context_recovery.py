"""Labeled offline context completion for recovery UI, never a model validation."""
import json
import re
import sqlite3
import sys
from pathlib import Path
from context_diagram import seed


def plans(root):
    return [json.loads(path.read_text()) for path in
            (root / ".kuzushi/v3/campaigns").glob("*/plan.json")]


def context_plan(root):
    matches = [plan for plan in plans(root) if plan.get("kind") == "context-study"]
    assert len(matches) == 1, "Recovery must preserve the single context plan"
    return matches[0]


def complete_fixture(root, evidence):
    plan = context_plan(root)
    assert len(plan["jobs"]) == 3
    seed(root, evidence)
    manifest_path = root / ".kuzushi/threat-models/manifest.json"
    manifest = json.loads(manifest_path.read_text())
    refs = json.loads((evidence / "context-refs.json").read_text())
    model = next(model for model in manifest["models"]
                 if model["modelId"] == refs["selected"]["modelId"])
    revision = next(revision for revision in model["revisions"]
                    if revision["revisionId"] == refs["selected"]["revisionId"])
    revision["runId"] = "labeled-fixture-context-result"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    queue = {"jobs": {job["jobId"]: {
        "state": "completed", "attempts": 1,
        "runId": "labeled-fixture-context-result" if job["jobId"] == "context-001"
        else "labeled-fixture-" + job["jobId"],
    } for job in plan["jobs"]}}
    (root / ".kuzushi/v3/campaigns" / plan["campaignId"] / "queue.json").write_text(
        json.dumps(queue, indent=2) + "\n")
    (evidence / "resume-command.txt").write_text("campaign " + plan["campaignId"])
    verify(root, evidence, "completed-fixture")


def remove_fixture_association(root, evidence):
    path = root / ".kuzushi/threat-models/manifest.json"
    manifest = json.loads(path.read_text())
    for model in manifest["models"]:
        for revision in model["revisions"]:
            if revision.get("runId") == "labeled-fixture-context-result":
                revision["runId"] = None
    path.write_text(json.dumps(manifest, indent=2) + "\n")
    verify(root, evidence, "missing-fixture")


def fail_fixture(root, evidence):
    plan = context_plan(root)
    path = root / ".kuzushi/v3/campaigns" / plan["campaignId"] / "queue.json"
    queue = json.loads(path.read_text())
    queue["jobs"]["context-001"].update(state="failed", reason="labeled fixture refusal")
    path.write_text(json.dumps(queue, indent=2) + "\n")
    verify(root, evidence, "failed-fixture")


def verify(root, evidence, stage):
    plan = context_plan(root)
    refs = json.loads((evidence / "context-refs.json").read_text())
    manifest = json.loads((root / ".kuzushi/threat-models/manifest.json").read_text())
    assert manifest["active"] == refs["active"]
    assert plan["workers"] == 1 and len(plan["jobs"]) == 3
    scans = [plan for plan in plans(root) if plan.get("kind") == "scan-batch"]
    if stage in ("selected", "missing-fixture", "resumed", "failed-fixture"):
        assert len(scans) == 1
        assert scans[0]["baseInput"]["threatModelRef"] == refs["selected"]
        assert scans[0]["investigationId"] == plan["investigationId"]
        assert scans[0]["trialsPlanned"] == 3
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=ro", uri=True) as connection:
        approvals = list(connection.execute(
            "select approval_json from investigation_allowance_revisions where investigation_id=?",
            (plan["investigationId"],)))
        assert len(approvals) == 1, "Reviewing a result must not create another allowance"
        assert json.loads(approvals[0][0])["limits"] == {"maxProviderCalls": 5, "protectedReviewCalls": 2}
        for table in ("investigation_work_attempts", "investigation_call_reservations"):
            assert connection.execute("select count(*) from " + table).fetchone()[0] == 0
    if stage == "resumed":
        ansi = next(evidence.glob("*-recovered-missing.ansi")).read_text()
        for sgr in re.findall(r"\x1b\[([\d;]*)m", ansi):
            assert not any(30 <= int(code) <= 38 or 40 <= int(code) <= 48
                           or 90 <= int(code) <= 107 for code in sgr.split(";") if code)
    (evidence / (stage + "-check.json")).write_text(json.dumps({
        "fixtureKind": "imported context and injected completed queue; no generator ran",
        "stage": stage, "campaignId": plan["campaignId"],
        "investigationId": plan["investigationId"], "selected": refs["selected"],
        "active": manifest["active"], "actualJobsStarted": 0, "providerCalls": 0,
        "injectedQueueCompletions": 3,
    }, indent=2) + "\n")


if __name__ == "__main__":
    root, evidence, action = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if action == "seed":
        evidence.mkdir(parents=True, exist_ok=True)
        (root / "reader.py").write_text('print("Labeled diagram fixture")\n')
    elif action == "complete":
        complete_fixture(root, evidence)
    elif action == "remove-result":
        remove_fixture_association(root, evidence)
    elif action == "fail-job":
        fail_fixture(root, evidence)
    else:
        verify(root, evidence, action)
