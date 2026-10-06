"""Real finite scanner execution with intercepted transport and synthetic findings."""
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True
import map_accounting


def seed(root, evidence, home):
    map_accounting.seed(root, evidence)
    repo = Path(__file__).resolve().parents[3]
    shutil.copyfile(repo / "scripts/devex/fixtures/study_provider.mjs", evidence / "provider.mjs")
    credentials = home / ".kuzushi/oauth-credentials.json"
    credentials.parent.mkdir(parents=True, exist_ok=True)
    credentials.write_text(json.dumps({"openai-codex": {
        "access": "offline-study-fixture", "expires": 99999999999999,
    }}) + "\n")
    credentials.chmod(0o600)
    command = ["node", "--import", str(evidence / "provider.mjs"), str(repo / "scripts/langgraph-bridge.mjs")]
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('model = "openai-codex:gpt-5.5"\n[runtime]\nthinking_level = "medium"\n'
                      + 'langgraph_bridge_command = ' + json.dumps(command) + '\n'
                      + '[runtime.anthropic_oauth]\ncredentials_path = ' + json.dumps(str(credentials)) + '\n'
                      + 'allow_env_token = false\n')


def load_plan(root):
    plans = [json.loads(path.read_text()) for path in (root / ".kuzushi/v3/campaigns").glob("*/plan.json")]
    scans = [plan for plan in plans if plan.get("kind") == "scan-batch"]
    assert len(scans) == 1, "The journey prepares exactly one discovery plan"
    return scans[0]


def query(binary, root, args):
    result = subprocess.run([binary, "--target", str(root), *args, "--json"],
                            text=True, capture_output=True, timeout=30, check=True)
    return json.loads(result.stdout)


def verify_plan(root, evidence, stage, allowance_calls=6, completed_calls=4, work_attempts=None):
    plan = load_plan(root)
    fixture = json.loads((root / ".kuzushi/v3/context-map-fixture.json").read_text())
    assert plan["investigationId"] == fixture["investigationId"]
    assert plan["baseInput"]["threatModelRef"] == fixture["generated"]
    assert len(plan["jobs"]) == 3 and plan["workers"] == 1
    assert plan["baseInput"]["tasks"] == ["agentic"]
    assert all(plan["baseInput"][key] is False for key in ["triage", "verify", "autoPatch"])
    (evidence / "scan-command.txt").write_text("campaign " + plan["campaignId"])
    (evidence / "batch-command.txt").write_text("batch " + plan["campaignId"])
    db = root / ".kuzushi/v3/index.sqlite3"
    with sqlite3.connect(db.as_uri() + "?mode=ro", uri=True) as connection:
        rows = connection.execute("select approval_json from investigation_allowance_revisions order by revision").fetchall()
        assert len(rows) == (1 if stage == "draft" else 2)
        if stage != "draft":
            approval = json.loads(rows[-1][0])
            assert approval["limits"] == {"maxProviderCalls": allowance_calls, "protectedReviewCalls": 2}
            assert approval["workPlan"]["campaignId"] == plan["campaignId"]
        expected = completed_calls if stage == "finished" else 1
        assert connection.execute("select count(*) from investigation_call_reservations").fetchone()[0] == expected
        attempts = expected if work_attempts is None else work_attempts
        assert connection.execute("select count(*) from investigation_work_attempts").fetchone()[0] == attempts
    return plan


def verify_finished(root, evidence):
    plan = verify_plan(root, evidence, "finished")
    state = root / ".kuzushi/v3"
    queue = json.loads((state / "campaigns" / plan["campaignId"] / "queue.json").read_text())
    assert all(job["state"] == "completed" for job in queue["jobs"].values())
    calls = [json.loads(line) for line in (evidence / "provider-calls.jsonl").read_text().splitlines()]
    assert len(calls) == 3 and len({call["bridgePid"] for call in calls}) == 3
    assert all(not call["hasAssistantHistory"] and not call["hasOtherActiveContext"] for call in calls)
    assert all(call["hasGeneratedContext"] for call in calls)
    assert len({call["inputSha256"] for call in calls}) == 1
    assert len({call["instructionsSha256"] for call in calls}) == 1
    report = query(os.environ["KUZUSHI_NATIVE_BIN"], root, ["findings", "batch", plan["campaignId"]])
    assert (report["completed"], report["planned"], report["failed"], report["pending"]) == (3, 3, 0, 0)
    assert sorted(row["seen"] for row in report["rows"]) == [1, 2]
    for row in report["rows"]:
        label = "recurring" if row["seen"] == 2 else "later-only"
        (evidence / ("open-" + label + ".txt")).write_text("open " + row["representativeFingerprint"])
    (evidence / "occurrence-report.json").write_text(json.dumps(report, indent=2) + "\n")
    rows = query(os.environ["KUZUSHI_NATIVE_BIN"], root, ["findings"])
    (evidence / "findings.json").write_text(json.dumps(rows, indent=2) + "\n")
    (evidence / "finished-receipt.json").write_text(json.dumps({
        "campaignId": plan["campaignId"], "discoveryCalls": 3, "liveProviderCalls": 0,
        "distinctBridgeProcesses": 3, "contextCalls": 1, "protectedReviewCalls": 2,
        "queueCompletionInjected": False, "findingsAreSynthetic": True,
    }, indent=2) + "\n")


def verify_report(root, evidence):
    exported = json.loads((root / ".kuzushi/reports/findings.json").read_text())
    assert exported["count"] == 2
    for row in exported["findings"]:
        serialized = json.dumps(row)
        if "Offline recurring test observation" in serialized:
            assert "false_positive" in serialized and "Labeled synthetic greeting observation" in serialized
        else:
            assert "Offline later-only test observation" in serialized
            assert "deferred" in serialized and "Labeled offline workflow decision" in serialized
    verify_finished(root, evidence)
    (evidence / "report-receipt.json").write_text(json.dumps({
        "findings": 2, "reviewDecisions": 2, "exportReadFromDisk": True,
        "liveProviderCalls": 0, "findingsAreSynthetic": True,
    }, indent=2) + "\n")


def verify_scan_selection(root, evidence):
    path = root / ".kuzushi/v3/workflow/phase-attempts.jsonl"
    events = [json.loads(line) for line in path.read_text().splitlines()]
    scans = [event for event in events if event["event"] == "phase_attempt_completed" and event["phase"] == "scan"]
    assert len(scans) == 1 and scans[0]["outcome"] == "completed"
    plan = load_plan(root)
    expected = {plan["campaignId"] + "-trial-" + f"{trial:03}" + "-a1" for trial in range(1, 4)}
    assert set(scans[0]["runRefs"]) == expected
    selected = [event for event in events if event["event"] == "phase_attempt_disposition_recorded"
                and event["attemptId"] == scans[0]["attemptId"]]
    assert len(selected) == 1 and selected[0]["disposition"] == {
        "kind": "selected", "acknowledged_partial": False,
    }
    verify_finished(root, evidence)
    (evidence / "scan-selection-receipt.json").write_text(json.dumps({
        "scanAttempts": 1, "acceptedRuns": 3, "operatorExplicitlySelected": True,
        "liveProviderCalls": 0, "findingsAreSynthetic": True,
    }, indent=2) + "\n")


if __name__ == "__main__":
    root, evidence, action = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if action == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    elif action == "report":
        verify_report(root, evidence)
    elif action == "selected":
        verify_scan_selection(root, evidence)
    elif action == "finished":
        deadline = time.monotonic() + 60
        while True:
            try:
                verify_finished(root, evidence)
                break
            except (AssertionError, FileNotFoundError):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.25)
    else:
        verify_plan(root, evidence, action)
