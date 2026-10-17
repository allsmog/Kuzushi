"""Actual local policy scans with an explicitly disabled check, then covered absence."""
import hashlib
import json
import sqlite3
import sys
from pathlib import Path


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def source(root):
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in ["package.json", "main.rs", "LICENSE"]}


def prepare(root, evidence):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "package.json").write_text(json.dumps({"name": "owned-policy-fixture", "license": "MIT",
        "scripts": {"postinstall": "touch must-not-execute"}}) + "\n")
    (root / "main.rs").write_text("// Owned inert policy fixture. Never executed.\n")
    (root / "LICENSE").write_text("MIT License\n")
    save(evidence, "expected-source", source(root))


def edit_header(root, evidence):
    (root / "main.rs").write_text("// SPDX-License-Identifier: MIT\n// Planned inert metadata edit.\n")
    save(evidence, "expected-source", source(root))


def results(root):
    values = {}
    for path in (root / ".kuzushi/v3/runs").glob("*/result.json"):
        value = json.loads(path.read_text())
        if "manifestsScanned" in value.get("data", {}):
            values[path.parent.name] = value
    return values


def ledger(root):
    path = root / ".kuzushi/v3/index.sqlite3"
    with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        counts = {name: db.execute("select count(*) from " + name).fetchone()[0] if name in tables else 0
                  for name in ["finding_observations", "review_decisions", "investigation_call_reservations", "investigation_work_attempts"]}
        counts["statuses"] = [row[0] for row in db.execute("select current_status from stable_findings")]
    assert counts["investigation_call_reservations"] == counts["investigation_work_attempts"] == 0
    assert not (root / "must-not-execute").exists()
    return counts


def inspect(root, evidence, stage):
    assert source(root) == json.loads((evidence / "expected-source.json").read_text())
    values = results(root)
    expected = {"first": 1, "disabled": 2, "covered": 3, "restarted": 3}[stage]
    assert len(values) == expected, (stage, values)
    base = [(run, value) for run, value in values.items() if value["data"]["count"] == 1]
    assert len(base) == 1
    base_run, base_value = base[0]
    disabled, covered = [], []
    for run, value in values.items():
        assert value["status"] == "completed"
        data = value["data"]
        assert data["manifestsScanned"] == 1
        observations = json.loads((root / ".kuzushi/v3/runs" / run / "findings.json").read_text())
        assert len(observations) == data["count"]
        receipt = data["phaseStages"][0]
        assert receipt["outcome"] == "completed"
        scan = receipt["scan"]
        assert scan["artifactDelta"] == [{"runRef": run, "path": "findings.json"}]
        assert sum(row["count"] for row in scan.get("severityCounts", [])) == len(observations)
        assert scan["plan"]["engines"] == ["license-scan"] and not scan["scope"].get("paths")
        engine = scan["engines"][0]
        assert engine["engine"] == "license-scan" and engine["outcome"] == "complete"
        assert engine["runRef"] == run and data["persisted"]["runId"] == run
        assert len(data["treeHash"]) == 64 and data["snapshotHash"]
        enabled = "license-scan/missing-spdx-header" in engine["ruleIds"]
        if data["count"] == 1:
            assert enabled and data["findings"][0]["ruleId"] == "license-scan/missing-spdx-header"
        elif enabled:
            covered.append((run, value))
        else:
            disabled.append((run, value))
    if expected >= 2:
        assert len(disabled) == 1
        run, value = disabled[0]
        assert value["data"]["treeHash"] == base_value["data"]["treeHash"]
        (evidence / "disabled-compare.txt").write_text(f"runs diff {base_run} {run}")
    if expected == 3:
        assert len(covered) == 1
        run, value = covered[0]
        assert value["data"]["treeHash"] != base_value["data"]["treeHash"]
        (evidence / "covered-compare.txt").write_text(f"runs diff {base_run} {run}")
    counts = ledger(root)
    assert counts["finding_observations"] == 1
    assert counts["review_decisions"] == (0 if stage == "first" else 1)
    assert counts["statuses"] == (["stale"] if expected == 3 else ["open"]), counts
    save(evidence, stage + "-check", {"runs": sorted(values), "providerRequests": 0,
        "actualLocalScanner": True, "scriptedReviewControls": True, "sourceExecuted": False, **counts})


root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
if stage == "prepare":
    prepare(root, evidence)
elif stage == "edit-header":
    edit_header(root, evidence)
else:
    inspect(root, evidence, stage)
