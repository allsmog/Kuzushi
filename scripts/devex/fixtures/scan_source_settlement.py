"""Installed local scanner, planned inert source edits, partial coverage and recovery."""
import hashlib
import json
import shutil
import sqlite3
import sys
import time
from pathlib import Path


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def source(root):
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in ["src/marker.py", "README.md"]}


def prepare(root, evidence):
    binary = shutil.which("semgrep")
    assert binary, "Installed local Semgrep is required"
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "src").mkdir(exist_ok=True)
    (root / "src/marker.py").write_text("# Owned inert metadata fixture. Never executed.\nowned_fixture_marker('baseline')\n")
    (root / "README.md").write_text("Owned source settlement fixture.\n")
    rules = evidence / "owned-local-rules.yaml"
    rules.write_text("rules:\n- id: owned-source-marker\n  languages: [python]\n"
                     "  message: Owned source settlement marker, not a vulnerability verdict\n"
                     "  severity: WARNING\n  pattern: owned_fixture_marker($X)\n")
    wrapper = evidence / "owned-scanner.py"
    wrapper.write_text(f"#!{sys.executable}\n" +
        "import os,sys,time\nfrom pathlib import Path\n" +
        f"evidence=Path({str(evidence)!r})\n" +
        "if '--version' not in sys.argv and (evidence/'mode.txt').read_text().strip()=='drift':\n"
        " (evidence/'scanner-entered').write_text('analysis started after source capture')\n"
        " deadline=time.monotonic()+25\n"
        " while not (evidence/'scanner-release').exists():\n"
        "  if time.monotonic()>=deadline: raise SystemExit('Owned scanner handshake timed out')\n"
        "  time.sleep(0.02)\n" +
        f"os.execv({binary!r},[{binary!r}]+sys.argv[1:])\n")
    wrapper.chmod(0o700)
    (evidence / "mode.txt").write_text("stable")
    command = "run sast:scan " + json.dumps({"taskMode": "manual", "tasks": ["semgrep"],
        "semgrepBinary": str(wrapper), "semgrepConfig": [str(rules)], "semgrepJobs": 1,
        "semgrepTimeoutMs": 30000, "triage": False, "verify": False, "autoPatch": False})
    (evidence / "scan-command.txt").write_text(command)
    save(evidence, "expected-source", source(root))


def prepare_drift(root, evidence):
    (root / "src/marker.py").write_text("# Planned inert edit removes the labeled metadata marker.\n")
    (evidence / "mode.txt").write_text("drift")
    save(evidence, "expected-source", source(root))


def release_with_edit(root, evidence):
    deadline = time.monotonic() + 20
    while not (evidence / "scanner-entered").is_file():
        assert time.monotonic() < deadline, "Scanner did not reach the owned source-edit point"
        time.sleep(0.05)
    (root / "README.md").write_text("Planned operator edit while local analysis is active.\n")
    save(evidence, "expected-source", source(root))
    (evidence / "scanner-release").write_text("continue local analysis")


def results(root):
    values = {}
    for path in (root / ".kuzushi/v3/runs").glob("*/result.json"):
        value = json.loads(path.read_text())
        if value.get("data", {}).get("engines") == ["semgrep"]:
            values[path.parent.name] = value
    return values


def ledger(root):
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        counts = {name: db.execute("select count(*) from " + name).fetchone()[0] if name in tables else 0
                  for name in ["finding_observations", "review_decisions", "investigation_call_reservations", "investigation_work_attempts"]}
        counts["findingStatuses"] = [row[0] for row in db.execute("select current_status from stable_findings")]
        counts["runStatuses"] = dict(db.execute("select run_id,status from run_states"))
    assert counts["investigation_call_reservations"] == counts["investigation_work_attempts"] == 0
    return counts


def inspect(root, evidence, stage):
    assert source(root) == json.loads((evidence / "expected-source.json").read_text())
    values = results(root)
    completed = [(run, v) for run, v in values.items() if v.get("status") == "completed"]
    partial = [(run, v) for run, v in values.items() if v.get("status") == "partial"]
    expected = {"baseline": (1, 0, 0), "deferred": (1, 0, 1), "partial": (1, 1, 1),
        "partial-report": (1, 1, 1), "complete": (2, 1, 1), "restarted": (2, 1, 1)}[stage]
    counts = ledger(root)
    assert (len(completed), len(partial), counts["review_decisions"]) == expected
    assert counts["finding_observations"] == 1
    assert counts["findingStatuses"] == (["stale"] if stage in ["complete", "restarted"] else ["open"])
    for run, value in values.items():
        data = value["data"]
        assert len(data["treeHash"]) == 64 and data["snapshotHash"]
        receipt = data["phaseStages"][0]
        assert receipt["outcome"] == value["status"]
        assert counts["runStatuses"][run] == value["status"]
        assert receipt["scan"]["engines"][0]["engine"] == "semgrep"
        assert receipt["scan"]["engines"][0]["outcome"] == "complete"
        if value["status"] == "partial":
            assert data["findingsCount"] == 0
            assert "source changed" in json.dumps(value).lower()
    if len(completed) == 2:
        stable = next(v for _, v in completed if v["data"]["findingsCount"] == 0)
        assert stable["data"]["treeHash"] != partial[0][1]["data"]["treeHash"]
    save(evidence, stage + "-check", {"runIds": sorted(values), "completed": len(completed),
        "partial": len(partial), "providerCalls": 0, "installedLocalScanner": True,
        "scriptedReviewControls": True, "sourceExecuted": False, **counts})


def wait_for_inspection(root, evidence, stage):
    deadline = time.monotonic() + 20
    while True:
        try:
            inspect(root, evidence, stage)
            return
        except (AssertionError, FileNotFoundError, json.JSONDecodeError, sqlite3.OperationalError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.1)


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "prepare": prepare(root, evidence)
    elif stage == "prepare-drift": prepare_drift(root, evidence)
    elif stage == "release-with-edit": release_with_edit(root, evidence)
    elif stage == "stable": (evidence / "mode.txt").write_text("stable")
    else: wait_for_inspection(root, evidence, stage)
