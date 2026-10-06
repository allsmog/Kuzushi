"""Installed local Semgrep output followed by a labeled stop seam. No provider work."""
import json
import os
import re
import shutil
import sqlite3
import sys
import time
from pathlib import Path
import map_context


def seed(root, evidence):
    binary = shutil.which("semgrep")
    assert binary, "Installed Semgrep is required for the retained observation"
    for name in ("a", "b", "c"):
        (root / name).mkdir(exist_ok=True)
        (root / name / "matched.py").write_text("fixture_call('labeled local source fixture')\n")
    rules = evidence / "stop-local-rules.yaml"
    rules.write_text("rules:\n- id: labeled-retained-rule\n  languages: [python]\n"
                     "  message: Labeled retained local observation\n  severity: WARNING\n"
                     "  pattern: fixture_call($X)\n")
    wrapper = evidence / "labeled-stop-scanner.py"
    wrapper.write_text(f"#!{sys.executable}\n" +
        "import json, os, sys, time\nfrom pathlib import Path\n" +
        f"evidence = Path({str(evidence)!r})\n" +
        "mode = (evidence / 'stop-mode.txt').read_text().strip()\n" +
        "scope = Path.cwd().name\n" +
        "with (evidence / 'stop-invocations.jsonl').open('a') as log:\n"
        "    log.write(json.dumps({'mode': mode, 'scope': scope}) + '\\n')\n" +
        "if scope == 'b':\n"
        "    (evidence / (mode + '-waiting')).write_text('labeled stop seam')\n"
        "    if mode == 'failed':\n"
        "        print('Labeled scanner failure after retained scope a', file=sys.stderr)\n"
        "        sys.exit(2)\n"
        "    time.sleep(120)\n"
        "    sys.exit(2)\n" +
        f"os.execv({binary!r}, [{binary!r}] + sys.argv[1:])\n")
    wrapper.chmod(0o755)
    map_context.seed(root, evidence)
    (evidence / "stop-mode.txt").write_text("failed")
    command = "run sast:scan " + json.dumps({
        "taskMode": "manual", "tasks": ["semgrep"], "paths": ["a", "b", "c"],
        "semgrepBinary": str(wrapper), "semgrepConfig": [str(rules)],
        "triage": False, "verify": False, "autoPatch": False,
    })
    (evidence / "stop-command.txt").write_text(command)


def waiting(evidence):
    (evidence / "stop-mode.txt").write_text("canceled")


def wait_seam(evidence):
    for _ in range(45):
        if (evidence / "canceled-waiting").is_file():
            return
        time.sleep(1)
    raise RuntimeError("Cancellation seam was not reached")


def stopped_result(root, status):
    for _ in range(45):
        events_path = root / ".kuzushi/v3/workflow/phase-attempts.jsonl"
        events = [json.loads(line) for line in events_path.read_text().splitlines()] if events_path.is_file() else []
        attempts = [event for event in events if event.get("event") == "phase_attempt_completed"
                    and event.get("phase") == "scan" and event.get("outcome") == status]
        for path in (root / ".kuzushi/v3/runs").glob("*/result.json"):
            result = json.loads(path.read_text())
            if result.get("status") == status and result.get("data", {}).get("nativeCoverage") and attempts:
                return path.parent, result, events
        time.sleep(1)
    raise RuntimeError("Stopped run did not publish its terminal receipt")


def verify(root, evidence, stage):
    status = "canceled" if stage in ("canceled", "restarted") else "failed"
    run, result, events = stopped_result(root, status)
    data = result["data"]
    assert data["findingsCount"] == 1
    assert data["nativeCoverage"]["schemaVersion"] == 2
    engines = data["nativeCoverage"]["engines"]
    assert [job["scope"] for job in engines] == ["a", "b", "c"]
    assert [job["disposition"] for job in engines] == ["complete", status, "not_started"]
    assert json.loads((run / "native-coverage.json").read_text()) == data["nativeCoverage"]
    observations = json.loads((run / "findings.json").read_text())
    assert len(observations) == 1 and observations[0]["file_path"] == "a/matched.py"
    (evidence / "retained-stop-finding.txt").write_text("open " + observations[0]["fingerprint"])
    summary = json.loads((run / "run.json").read_text())
    assert summary["status"] == status and summary["findings"] == 1
    assert data["phaseStages"][0]["scan"]["findingDelta"]["added"] + data["phaseStages"][0]["scan"]["findingDelta"]["updated"] == 1
    assert len(data["treeHash"]) == 64 and data["snapshotHash"]
    scans = [event for event in events if event.get("event") == "phase_attempt_completed" and event.get("phase") == "scan"]
    assert len(scans) == (1 if stage == "failed" else 2)
    scan_ids = {event["attemptId"] for event in scans}
    assert not any(event.get("event") == "phase_attempt_disposition_recorded"
                   and event.get("attemptId") in scan_ids and event["disposition"]["kind"] == "selected" for event in events)
    calls = [json.loads(line) for line in (evidence / "stop-invocations.jsonl").read_text().splitlines()]
    mode_calls = [call for call in calls if call["mode"] == status]
    assert [call["scope"] for call in mode_calls] == ["a", "b"], calls
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=ro", uri=True) as connection:
        assert connection.execute("select status from run_states where run_id = ?", (run.name,)).fetchone()[0] == status
    if stage == "restarted":
        ansi = next(evidence.glob("*-restarted-stop.ansi")).read_text()
        for sgr in re.findall(r"\x1b\[([\d;]*)m", ansi):
            assert not any(30 <= int(code) <= 38 or 40 <= int(code) <= 48 or 90 <= int(code) <= 107 for code in sgr.split(";") if code)
    (evidence / f"stop-{stage}-receipt.json").write_text(json.dumps({
        "runId": run.name, "status": status, "retainedFindings": 1,
        "scanJobsApproved": 3, "scannerInvocations": mode_calls,
        "liveProviderCalls": 0, "source": "installed Semgrep local rule on a; labeled failure/cancellation seam on b; c not started",
        "treeHash": data["treeHash"], "snapshotHash": data["snapshotHash"],
    }, indent=2) + "\n")


if __name__ == "__main__":
    root, evidence, action = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if action == "seed": seed(root, evidence)
    elif action == "prepare-cancel": waiting(evidence)
    elif action == "wait-cancel": wait_seam(evidence)
    else: verify(root, evidence, action)
