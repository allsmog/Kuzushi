"""Exact accepted source membership through real tools. No provider requests."""
import json
import os
import shutil
import sqlite3
import sys
import time
from pathlib import Path
from context_comparison import run_tool
import map_context


def seed(root, evidence):
    assert root.name == "fixture-target"
    for name in ("app.py", "config.env"):
        (root / name).unlink(missing_ok=True)
    for name in ("[route].py", "root file.py", "excluded.py"):
        (root / name).write_text("fixture_call('Labeled static analysis input')\n")
    map_context.seed(root, evidence)
    binary = os.environ["KUZUSHI_NATIVE_BIN"]
    first = run_tool(binary, root, evidence, "scope-create", "pack:scopes", {})["data"]
    edited = run_tool(binary, root, evidence, "scope-exclusion", "pack:scopes", {
        "operation": "edit", "proposalRef": first["reference"],
        "edit": {"action": "exclude-path", "path": "excluded.py", "reason": "Explicit labeled fixture exclusion"},
    })["data"]
    accepted = run_tool(binary, root, evidence, "scope-accept", "pack:scopes", {
        "operation": "accept", "proposalRef": edited["reference"],
        "acknowledgements": {"inventoryLimitations": True, "exclusions": True, "overlappingDiscovery": False},
    })["data"]
    reference = {"proposal": accepted["reference"], "scopeId": "repository"}
    (evidence / "scope-reference.json").write_text(json.dumps(reference))
    semgrep = shutil.which("semgrep")
    assert semgrep, "This journey requires installed Semgrep"
    rules = evidence / "exact-rule.yml"
    rules.write_text("rules:\n- id: labeled-exact-rule\n  languages: [python]\n"
                     "  message: Labeled static analysis input\n  severity: WARNING\n"
                     "  pattern: fixture_call($X)\n")
    command = {"taskMode": "manual", "tasks": ["semgrep"], "scanScopeRef": reference,
               "semgrepBinary": semgrep, "semgrepConfig": [str(rules)],
               "threatModelRef": None, "triage": False, "verify": False, "autoPatch": False}
    (evidence / "scan-command.txt").write_text("run sast:scan " + json.dumps(command))


def verify(root, evidence, stage):
    reference = json.loads((evidence / "scope-reference.json").read_text())
    state = root / ".kuzushi/v3"
    plans = [json.loads(path.read_text()) for path in (state / "campaigns").glob("*/plan.json")]
    assert len(plans) == 1
    plan = plans[0]
    assert plan["baseInput"]["scanScopeRef"] == reference
    assert plan["baseInput"]["tasks"] == ["secret-scan"]
    assert plan["workers"] == 1 and len(plan["jobs"]) == 3
    assert all(job["input"]["scanScopeRef"] == reference for job in plan["jobs"])
    assert not (state / "campaigns" / plan["campaignId"] / "queue.json").exists()
    scans = [path.parent for path in (state / "runs").glob("*/run.json")
             if json.loads(path.read_text()).get("tool") == "sast:scan"]
    completed = [run for run in scans if json.loads((run / "run.json").read_text()).get("status") == "completed"]
    if stage == "draft":
        assert not scans
    else:
        if stage == "scanned":
            for _ in range(45):
                if completed and (completed[0] / "result.json").is_file():
                    break
                time.sleep(1)
                scans = [path.parent for path in (state / "runs").glob("*/run.json")
                         if json.loads(path.read_text()).get("tool") == "sast:scan"]
                completed = [run for run in scans if json.loads((run / "run.json").read_text()).get("status") == "completed"]
        assert len(completed) == 1
        run = completed[0]
        result = json.loads((run / "result.json").read_text())
        assert result["data"]["findingsCount"] == 2, result
        saved = json.loads((run / "scan-input.json").read_text())
        assert saved["scanScopeRef"] == reference
        assert saved["tasks"] == ["semgrep"]
        coverage = result["data"]["nativeCoverage"]["engines"]
        assert len(coverage) == 1 and not coverage[0]["scanErrors"]
        findings = json.loads((run / "findings.json").read_text())
        rows = findings if isinstance(findings, list) else findings["findings"]
        paths = {row.get("filePath", row.get("file_path")) for row in rows}
        assert paths == {"[route].py", "root file.py"}, paths
    with sqlite3.connect((state / "index.sqlite3").as_uri() + "?mode=ro", uri=True) as connection:
        tables = {row[0] for row in connection.execute("select name from sqlite_master where type='table'")}
        for table in ("investigation_work_attempts", "investigation_call_reservations"):
            if table in tables:
                assert connection.execute(f"select count(*) from {table}").fetchone()[0] == 0
    (evidence / f"exact-scope-{stage}.json").write_text(json.dumps({
        "reference": reference, "plannedJobs": 3, "studyJobsStarted": 0,
        "standaloneNativeScansCompleted": len(completed), "providerCalls": 0,
        "sourceAnalysisOnly": True, "findingsUseLabeledLocalRules": True,
        "sourceContentChanged": stage in ("drift", "restarted"), "gitShaTransitionTested": False,
    }, indent=2) + "\n")


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "seed":
        seed(root, evidence)
    elif stage == "change-source":
        (root / "[route].py").write_text("fixture_call('Changed labeled source')\n")
    else:
        verify(root, evidence, stage)
