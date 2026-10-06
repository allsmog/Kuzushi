"""Accepted scope reaches the study report through real tools. No provider requests.

Source files are labeled static analysis input and are never executed.
"""
import hashlib
import json
import os
import shutil
import sqlite3
import sys
import time
from pathlib import Path
from context_comparison import run_tool
import map_context

EXCLUSION = "Explicit labeled fixture exclusion"


def seed(root, evidence):
    assert root.name == "fixture-target"
    (root / "excluded.py").write_text("fixture_call('Labeled excluded input')\n")
    map_context.seed(root, evidence)
    binary = os.environ["KUZUSHI_NATIVE_BIN"]
    first = run_tool(binary, root, evidence, "scope-create", "pack:scopes", {})["data"]
    edited = run_tool(binary, root, evidence, "scope-exclusion", "pack:scopes", {
        "operation": "edit", "proposalRef": first["reference"],
        "edit": {"action": "exclude-path", "path": "excluded.py", "reason": EXCLUSION},
    })["data"]
    accepted = run_tool(binary, root, evidence, "scope-accept", "pack:scopes", {
        "operation": "accept", "proposalRef": edited["reference"],
        "acknowledgements": {"inventoryLimitations": True, "exclusions": True, "overlappingDiscovery": False},
    })["data"]
    reference = {"proposal": accepted["reference"], "scopeId": "repository"}
    (evidence / "scope-reference.json").write_text(json.dumps(reference))


def state(root):
    return root / ".kuzushi/v3"


def single_plan(root):
    plans = [json.loads(path.read_text()) for path in (state(root) / "campaigns").glob("*/plan.json")]
    assert len(plans) == 1, "Exactly one finite study plan must exist"
    return plans[0]


def verify_draft(root, evidence):
    reference = json.loads((evidence / "scope-reference.json").read_text())
    plan = single_plan(root)
    assert plan["baseInput"]["scanScopeRef"] == reference
    assert plan["baseInput"]["tasks"] == ["secret-scan"]
    assert plan["workers"] == 1 and len(plan["jobs"]) == 3
    assert all(job["input"]["scanScopeRef"] == reference for job in plan["jobs"])
    return {"campaignId": plan["campaignId"], "plannedJobs": 3}


def ledger_counts(root):
    with sqlite3.connect((state(root) / "index.sqlite3").as_uri() + "?mode=ro", uri=True) as connection:
        tables = {row[0] for row in connection.execute("select name from sqlite_master where type='table'")}
        counts = {}
        for table in ("investigation_work_attempts", "investigation_call_reservations"):
            counts[table] = connection.execute(f"select count(*) from {table}").fetchone()[0] if table in tables else 0
    return counts


def verify_finished(root):
    plan = single_plan(root)
    queue = json.loads((state(root) / "campaigns" / plan["campaignId"] / "queue.json").read_text())
    assert all(job["state"] == "completed" for job in queue["jobs"].values()), queue
    counts = ledger_counts(root)
    assert counts["investigation_work_attempts"] == 3, counts
    assert counts["investigation_call_reservations"] == 0, "Offline journey admitted provider transport"
    return {"jobAttempts": 3, "providerCalls": 0}


def verify_attempt_recorded(root):
    """The detached dispatcher records the Scan attempt; the shell must notice on its own."""
    events = [json.loads(line) for line in
              (state(root) / "workflow/phase-attempts.jsonl").read_text().splitlines()]
    scans = [event for event in events if event.get("event") == "phase_attempt_completed"
             and event.get("phase") == "scan"]
    assert len(scans) == 1 and len(scans[0]["runRefs"]) == 3, "Study Scan attempt not yet recorded"
    return {"scanAttemptRuns": 3}


def export_paths(root):
    output = root / ".kuzushi/reports/findings.json"
    return output, output.with_name("findings.json.investigation.json")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_report(root, evidence, name):
    reference = json.loads((evidence / "scope-reference.json").read_text())
    output, receipt_path = export_paths(root)
    receipt = json.loads(receipt_path.read_text())
    embedded = json.loads(output.read_text())["metadata"]["investigation"]
    assert embedded == receipt, "Export and receipt must describe the same study"
    scope = receipt["scope"]
    assert scope["scanScopeRef"] == reference
    proposal = scope["acceptedScopeProposal"]
    assert proposal["reference"] == reference["proposal"]
    assert proposal["record"]["acceptance"] is not None
    assert proposal["coverage"]["discoveryMembers"]["repository"]["total"] > 0
    assert proposal["record"]["draft"]["exclusions"] == [{"path": "excluded.py", "reason": EXCLUSION}]
    assert receipt["occurrence"]["completed"] == 3
    (evidence / f"{name}-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return {"exportSha256": digest(output), "receiptSha256": digest(receipt_path)}


def verify_restarted(root, evidence):
    result = verify_report(root, evidence, "restarted")
    first = json.loads((evidence / "first-receipt.json").read_text())
    later = json.loads((evidence / "restarted-receipt.json").read_text())
    assert later["scope"]["acceptedScopeProposal"] == first["scope"]["acceptedScopeProposal"]
    return result


def verify_drift(root, evidence):
    assert (root / "reader.py").read_text().startswith('print("Changed labeled'), "Source change missing"
    result = verify_report(root, evidence, "drift")
    first = json.loads((evidence / "first-receipt.json").read_text())
    later = json.loads((evidence / "drift-receipt.json").read_text())
    assert later["campaignId"] == first["campaignId"]
    assert later["scope"]["acceptedScopeProposal"] == first["scope"]["acceptedScopeProposal"]
    original = [attempt["sourceIdentity"] for attempt in first["attempts"]]
    assert [attempt["sourceIdentity"] for attempt in later["attempts"]] == original
    result.update({"sourceContentChanged": True, "earlierStudyExported": True})
    return result


def damage(root, evidence):
    output, receipt_path = export_paths(root)
    shutil.move(str(state(root) / "scan-scopes"), str(evidence / "scan-scopes-moved"))
    (evidence / "pre-damage-export.json").write_text(json.dumps(
        {"exportSha256": digest(output), "receiptSha256": digest(receipt_path)}))


def verify_damaged(root, evidence):
    output, receipt_path = export_paths(root)
    before = json.loads((evidence / "pre-damage-export.json").read_text())
    assert digest(output) == before["exportSha256"], "Damaged evidence replaced the previous export"
    assert digest(receipt_path) == before["receiptSha256"], "Damaged evidence replaced the previous receipt"
    assert not (state(root) / "scan-scopes").exists()
    return {"previousExportPreserved": True}


def restore(root, evidence):
    shutil.move(str(evidence / "scan-scopes-moved"), str(state(root) / "scan-scopes"))


def record(evidence, stage, receipt):
    receipt.update({"stage": stage, "providerCalls": 0, "sourceAnalysisOnly": True})
    (evidence / f"report-scope-{stage}.json").write_text(json.dumps(receipt, indent=2) + "\n")


def run_stage(root, evidence, stage):
    actions = {
        "draft": lambda: verify_draft(root, evidence),
        "finished": lambda: verify_finished(root),
        "attempt-recorded": lambda: verify_attempt_recorded(root),
        "first": lambda: verify_report(root, evidence, "first"),
        "restarted": lambda: verify_restarted(root, evidence),
        "drift": lambda: verify_drift(root, evidence),
        "damaged": lambda: verify_damaged(root, evidence),
    }
    record(evidence, stage, actions[stage]())


def run_with_wait(root, evidence, stage, seconds):
    deadline = time.monotonic() + seconds
    while True:
        try:
            return run_stage(root, evidence, stage)
        except (AssertionError, FileNotFoundError, KeyError, json.JSONDecodeError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.25)


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "seed":
        seed(root, evidence)
    elif stage == "change-source":
        (root / "reader.py").write_text('print("Changed labeled Map fixture")\n')
    elif stage == "damage":
        damage(root, evidence)
    elif stage == "restore":
        restore(root, evidence)
    else:
        run_with_wait(root, evidence, stage, 45 if stage in ("finished", "attempt-recorded") else 10)
