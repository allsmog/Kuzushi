"""Real configuration rules, exact file membership and finite selected scopes."""
import json
import sqlite3
import sys
import time
from pathlib import Path

from cargo_audit import hashes, save
from iac_outcome_settlement import results
from scan_source_settlement import ledger


def prepare(root, evidence):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    selected = root / "selected"
    (selected / ".github/workflows").mkdir(parents=True)
    (root / "empty").mkdir()
    (selected / "Dockerfile").write_text("FROM owned:latest\nUSER nobody\n")
    (selected / ".github/workflows/owned.yml").write_text("permissions: write-all\n")
    (root / "Dockerfile").write_text("FROM excluded:latest\nUSER root\n")
    (selected / "cycle").symlink_to(selected, target_is_directory=True)
    save(evidence, "source-before", hashes(root))


def inspect(root, evidence, stage):
    assert hashes(root) == json.loads((evidence / "source-before.json").read_text())
    values = results(root)
    expected = {"all": 1, "deferred": 1, "docker": 2, "empty": 3, "restarted": 3}[stage]
    assert len(values) == expected
    counts = ledger(root)
    assert counts["finding_observations"] == (2 if expected == 1 else 3)
    assert counts["review_decisions"] == (0 if stage == "all" else 1)
    assert counts["findingStatuses"] == ["open", "open"]
    assert counts["investigation_call_reservations"] == counts["investigation_work_attempts"] == 0
    by_selection = {}
    for run, value in values.items():
        assert value["status"] == "completed"
        data = value["data"]
        scan = data["phaseStages"][0]["scan"]
        scope = scan["scope"]
        assert scope["target"] == str(root)
        assert scan["plan"] == {"selection": "direct", "engines": ["iac-scan"]}
        assert scan["artifactDelta"] == [{"runRef": run, "path": "findings.json"}]
        observations = json.loads((root / ".kuzushi/v3/runs" / run / "findings.json").read_text())
        assert len(observations) == data["count"]
        assert scope["inspectedFiles"] == data["inspectedFiles"]
        assert len(scope["inspectedFiles"]) == data["filesScanned"]
        assert data["sourceCheckCurrent"] is True and scan.get("cost") is None
        assert all(name.startswith("selected/") for name in scope["inspectedFiles"])
        assert all("cycle" not in name for name in scope["inspectedFiles"])
        key = (scope["paths"][0], data["kind"])
        by_selection[key] = run
        rules = scan["engines"][0]["ruleIds"]
        if data["kind"] == "dockerfile":
            assert len(rules) == 6 and all(name.startswith("iac-scan/dockerfile-") for name in rules)
        else:
            assert data["kind"] == "all" and len(rules) == 15
    base = by_selection[("selected", "all")]
    if expected >= 2:
        later = by_selection[("selected", "dockerfile")]
        (evidence / "docker-compare.txt").write_text(f"runs diff {base} {later}")
    if expected == 3:
        later = by_selection[("empty", "dockerfile")]
        assert values[later]["data"]["inspectedFiles"] == []
        (evidence / "empty-compare.txt").write_text(f"runs diff {base} {later}")
    save(evidence, stage + "-check", {"runs": sorted(values), "counts": counts,
        "exactInspectedFiles": True, "enabledRulesRecorded": True, "liveProviderRequests": 0,
        "sourceUnchanged": True, "targetSourceExecuted": False, "scriptedReviewControls": True})


def wait(root, evidence, stage):
    deadline = time.monotonic() + 25
    while True:
        try:
            inspect(root, evidence, stage)
            return
        except (AssertionError, FileNotFoundError, KeyError, json.JSONDecodeError, sqlite3.OperationalError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.1)


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "prepare": prepare(root, evidence)
    else: wait(root, evidence, stage)
