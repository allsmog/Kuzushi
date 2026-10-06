"""One installed whole-repository Semgrep job, explicit local rules, no model."""
import json
import re
import shutil
import sqlite3
import sys
import time
from pathlib import Path

import native_partial


def seed(root, evidence):
    native_partial.seed(root, evidence)
    command = "run semgrep:scan " + json.dumps({
        "binary": shutil.which("semgrep"),
        "config": str(evidence / "local-rules.yaml"),
    })
    (evidence / "standalone-scan-command.txt").write_text(command)


def wait_result(root):
    for _ in range(45):
        runs = [path.parent for path in (root / ".kuzushi/v3/runs").glob("*/run.json")
                if json.loads(path.read_text()).get("tool") == "semgrep:scan"]
        assert len(runs) <= 1, "This journey approves one whole-repository Semgrep job"
        if runs and (runs[0] / "result.json").is_file():
            result = json.loads((runs[0] / "result.json").read_text())
            summary = json.loads((runs[0] / "run.json").read_text())
            if (result.get("status") in ("partial", "failed", "completed")
                    and summary.get("status") in ("partial", "failed", "completed")
                    and native_partial.terminal_scan_receipt(root)):
                return runs[0], result
        time.sleep(1)
    raise RuntimeError("Standalone Semgrep did not publish a terminal result and Scan receipt")


def verify(root, evidence, stage):
    run, result = wait_result(root)
    assert result["status"] == "partial", result.get("summary")
    data = result["data"]
    assert data["count"] == 1 and data["persisted"]["runId"] == run.name
    assert data["scanErrors"] and "incompatible-fixture-rule" in data["scanErrors"][0]
    assert len(data["treeHash"]) == 64 and len(data["snapshotHash"]) == 64
    assert data["findings"][0]["file_path"] == "service/matched.py"
    assert json.loads((run / "run.json").read_text())["status"] == "partial"
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=ro", uri=True) as connection:
        assert connection.execute("select status from run_states where run_id = ?", (run.name,)).fetchone() == ("partial",)
        tables = {row[0] for row in connection.execute("select name from sqlite_master where type='table'")}
        for table in ("investigation_work_attempts", "investigation_call_reservations"):
            if table in tables:
                assert connection.execute(f"select count(*) from {table}").fetchone()[0] == 0
    events = [json.loads(line) for line in (root / ".kuzushi/v3/workflow/phase-attempts.jsonl").read_text().splitlines()]
    scans = [event for event in events if event.get("event") == "phase_attempt_completed" and event.get("phase") == "scan"]
    assert len(scans) == 1 and scans[0]["outcome"] == "partial"
    decisions = [event for event in events if event.get("event") == "phase_attempt_disposition_recorded"
                 and event.get("attemptId") == scans[0]["attemptId"]]
    if stage == "unselected":
        assert not decisions, "Partial work cannot become selected automatically"
    else:
        assert len(decisions) == 1 and decisions[0]["disposition"]["kind"] == "selected"
        assert decisions[0]["disposition"]["acknowledged_partial"] is True
    (evidence / "open-finding.txt").write_text("open " + data["findings"][0]["fingerprint"])
    if stage == "restarted":
        ansi = next(evidence.glob("*-restarted-scan.ansi")).read_text()
        for sgr in re.findall(r"\x1b\[([\d;]*)m", ansi):
            assert not any(30 <= int(code) <= 38 or 40 <= int(code) <= 48 or 90 <= int(code) <= 107
                           for code in sgr.split(";") if code)
    (evidence / f"standalone-{stage}-receipt.json").write_text(json.dumps({
        "engine": "installed Semgrep with explicit local rules", "stage": stage,
        "runId": run.name, "findings": 1, "coverageGaps": data["scanErrors"],
        "treeHash": data["treeHash"], "snapshotHash": data["snapshotHash"],
        "selected": stage != "unselected", "liveProviderCalls": 0,
        "scope": "whole repository", "remoteRuleSelectors": [],
    }, indent=2) + "\n")


if __name__ == "__main__":
    root, evidence, action = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if action == "seed":
        seed(root, evidence)
    else:
        verify(root, evidence, action)
