"""Owned license-policy observations, source edits, review and report recovery."""
import hashlib
import json
import sqlite3
import sys
import time
from pathlib import Path


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def sources(root):
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in ["package.json", "main.rs", "LICENSE"] if (root / name).exists()}


def prepare(root, evidence):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "package.json").write_text(json.dumps({"name":"owned-policy-fixture",
        "scripts":{"postinstall":"touch must-not-execute"}}) + "\n")
    (root / "main.rs").write_text("// SPDX-License-Identifier: MIT\n// Owned inert policy fixture. Never built or executed.\n")
    internal = root / ".kuzushi/generated"
    internal.mkdir(parents=True)
    (internal / "receipt.rs").write_text("// Internal analysis artifact, outside source policy.\n")
    save(evidence, "expected-source", sources(root))


def edit_source(root, evidence, action):
    if action == "license":
        value = json.loads((root / "package.json").read_text())
        value["license"] = "MIT"
        (root / "package.json").write_text(json.dumps(value) + "\n")
    if action == "oversize":
        with (root / "LICENSE").open("wb") as stream:
            stream.truncate(2 * 1024 * 1024 + 1)
    else:
        (root / "LICENSE").write_text("MIT License\n")
    save(evidence, "expected-source", sources(root))


def license_receipts(root):
    values = {}
    for path in (root / ".kuzushi/v3/runs").glob("*/result.json"):
        value = json.loads(path.read_text())
        data = value.get("data", {})
        if value.get("output", "").startswith("license-scan:") or data.get("tool") == "license-scan:scan" or data.get("engines") == ["license-scan"]:
            values[path.parent.name] = value
    return values


def counts(root):
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        value = {}
        for name in ["finding_observations", "review_decisions", "investigation_call_reservations", "investigation_work_attempts"]:
            value[name] = db.execute("select count(*) from " + name).fetchone()[0] if name in tables else 0
    assert value["investigation_call_reservations"] == value["investigation_work_attempts"] == 0
    assert not (root / "must-not-execute").exists()
    return value


def inspect(root, evidence, stage):
    assert sources(root) == json.loads((evidence / "expected-source.json").read_text())
    values = license_receipts(root)
    completed = [v for v in values.values() if v.get("status") == "completed"]
    failures = [v for v in values.values() if v.get("status") == "failed"]
    expected = {"first":(1,0,1,0), "second":(2,0,2,0), "third":(3,0,3,0), "deferred":(3,0,3,1),
        "clean":(4,0,3,1), "exported":(4,0,3,1), "failed":(4,1,3,1), "recovered":(5,1,3,1), "restarted":(5,1,3,1)}
    ledger = counts(root)
    actual = (len(completed), len(failures), ledger["finding_observations"], ledger["review_decisions"])
    assert actual == expected[stage], (actual, expected[stage], values)
    for value in completed:
        data = value["data"]
        if "manifestsScanned" in data:
            assert data["manifestsScanned"] == 1 and data["count"] in [0,1]
            assert all(row["ruleId"] == "license-scan/missing-license" for row in data["findings"])
        else:
            assert data["coreFindings"] == []
            receipt = data["phaseStages"][0]["scan"]
            assert receipt["engines"][0]["engine"] == "license-scan"
            assert receipt["engines"][0]["outcome"] == "complete"
    for value in failures:
        assert "2097152" in json.dumps(value) and "coreFindings" not in value.get("data", {})
    if stage in ["exported", "restarted"]:
        check_export(root, evidence)
    save(evidence, stage + "-check", {"completedScans":len(completed),"failedScans":len(failures),
        "sourceUnchangedByTools":True,"sourceExecuted":False,"providerRequests":0,"observationsAreSynthetic":False,
        "scriptedReviewControls":True,"runIds":sorted(values),**ledger})


def check_export(root, evidence):
    documents = []
    for path in (root / ".kuzushi/reports").glob("*.json"):
        value = json.loads(path.read_text())
        if value.get("count") == 1 and value.get("findings"):
            documents.append((path, value))
    assert documents, "The TUI must export its actual finding history"
    path, value = documents[-1]
    finding = value["findings"][0]
    assert finding["reviewDecision"] == "deferred", finding
    assert "Absence does not establish a fix" in finding["observationNote"], finding
    save(evidence, "report-check", {"path":str(path),"findings":1,"decision":"deferred",
        "absenceDoesNotEstablishFix":True,"fullFinding":finding})


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


def main():
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "prepare":
        prepare(root, evidence)
    elif stage in ["license", "oversize", "repair"]:
        edit_source(root, evidence, stage)
    else:
        wait_for_inspection(root, evidence, stage)


if __name__ == "__main__":
    main()
