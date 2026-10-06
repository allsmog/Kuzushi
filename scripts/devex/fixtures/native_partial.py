"""Installed Semgrep, local rules and an explicit omitted rule. No model work."""
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
    assert binary, "Installed Semgrep is required; do not substitute a fixture engine"
    service = root / "service"
    service.mkdir(exist_ok=True)
    (service / "matched.py").write_text("fixture_call('labeled source-analysis fixture')\n")
    (service / "malformed.py").write_text("def broken(:\n")
    rules = evidence / "local-rules.yaml"
    rules.write_text("rules:\n- id: labeled-local-rule\n  languages: [python]\n"
                     "  message: Labeled local rule fixture\n  severity: WARNING\n"
                     "  pattern: fixture_call($X)\n- id: incompatible-fixture-rule\n"
                     "  min-version: 999.0.0\n  languages: [python]\n"
                     "  message: Labeled omitted rule\n  severity: WARNING\n"
                     "  pattern: fixture_call($X)\n")
    map_context.seed(root, evidence)
    command = "run sast:scan " + json.dumps({
        "taskMode": "manual", "tasks": ["semgrep", "secret-scan"], "paths": ["service"],
        "semgrepBinary": binary, "semgrepConfig": [str(rules)],
        "triage": False, "verify": False, "autoPatch": False,
    })
    (evidence / "native-scan-command.txt").write_text(command)


def wait_result(root):
    for _ in range(45):
        runs = [path.parent for path in (root / ".kuzushi/v3/runs").glob("*/run.json")
                if json.loads(path.read_text()).get("tool") == "sast:scan"]
        assert len(runs) <= 1, "This journey approves exactly one native scan"
        if runs and (runs[0] / "result.json").is_file():
            result = json.loads((runs[0] / "result.json").read_text())
            summary = json.loads((runs[0] / "run.json").read_text())
            if (result.get("status") in ("partial", "failed", "completed")
                    and summary.get("status") in ("partial", "failed", "completed")
                    and terminal_scan_receipt(root)):
                return runs[0], result
        time.sleep(1)
    raise RuntimeError("Native run did not publish a terminal result")


def terminal_scan_receipt(root):
    path = root / ".kuzushi/v3/workflow/phase-attempts.jsonl"
    if not path.is_file():
        return False
    return any(event.get("event") == "phase_attempt_completed" and event.get("phase") == "scan"
               for event in (json.loads(line) for line in path.read_text().splitlines()))


def verify(root, evidence, stage):
    run, result = wait_result(root)
    assert result["status"] == "partial", result.get("summary")
    data = result["data"]
    assert data["findingsCount"] == 1
    assert data["nativeCoverage"]["engines"][0]["scope"] == "service"
    gaps = data["nativeCoverage"]["engines"][0]["scanErrors"]
    assert gaps and any("incompatible-fixture-rule" in gap for gap in gaps)
    assert data["nativeCoverage"]["engines"][1]["engine"] == "secret-scan"
    assert data["nativeCoverage"]["engines"][1]["scanErrors"] == []
    assert json.loads((run / "native-coverage.json").read_text()) == data["nativeCoverage"]
    saved = json.loads((run / "scan-input.json").read_text())
    assert saved["paths"] == ["service"] and saved["tasks"] == ["semgrep", "secret-scan"]
    assert saved["semgrepConfig"] == [str(evidence / "local-rules.yaml")]
    assert len(data["treeHash"]) == 64 and data["snapshotHash"]
    summary = json.loads((run / "run.json").read_text())
    assert summary["status"] == "partial"
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
    observations = json.loads((run / "findings.json").read_text())
    assert len(observations) == 1 and observations[0]["file_path"] == "service/matched.py"
    (evidence / "open-finding.txt").write_text("open " + observations[0]["fingerprint"])
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=ro", uri=True) as connection:
        tables = {row[0] for row in connection.execute("select name from sqlite_master where type='table'")}
        for table in ("investigation_work_attempts", "investigation_call_reservations"):
            if table in tables:
                assert connection.execute(f"select count(*) from {table}").fetchone()[0] == 0
    if stage == "restarted":
        ansi = next(evidence.glob("*-restarted-scan.ansi")).read_text()
        for sgr in re.findall(r"\x1b\[([\d;]*)m", ansi):
            assert not any(30 <= int(code) <= 38 or 40 <= int(code) <= 48 or 90 <= int(code) <= 107
                           for code in sgr.split(";") if code)
    (evidence / f"native-{stage}-receipt.json").write_text(json.dumps({
        "engine": "installed Semgrep with a local fixture rule", "stage": stage,
        "runId": run.name, "findings": 1, "coverageGaps": gaps,
        "treeHash": data["treeHash"], "snapshotHash": data["snapshotHash"],
        "selected": stage != "unselected", "liveProviderCalls": 0,
        "scope": ["service"], "remoteRuleSelectors": [],
    }, indent=2) + "\n")


if __name__ == "__main__":
    root, evidence, action = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if action == "seed":
        seed(root, evidence)
    else:
        verify(root, evidence, action)
