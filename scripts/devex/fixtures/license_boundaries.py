"""Actual monorepo metadata scans, repetitions and retained human review."""
import hashlib
import json
import sqlite3
import sys
import time
from pathlib import Path

import license_audit as audit


SOURCE_PATHS = ["LICENSE", "client/package.json", "client/example.rs",
                "service/package.json", "service/example.rs"]


def sources(root):
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in SOURCE_PATHS}


def prepare(root, evidence):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "LICENSE").write_text("Owned inert text.\n")
    for name, license in [("client", "MIT"), ("service", "Apache-2.0")]:
        directory = root / name
        directory.mkdir()
        (directory / "package.json").write_text(json.dumps({"name": name, "license": license,
            "scripts": {"postinstall": "touch must-not-execute"}}) + "\n")
        (directory / "example.rs").write_text(f"// SPDX-License-Identifier: {license}\n// Owned inert source.\n")
    audit.save(evidence, "expected-source", sources(root))


def edit_header(root, evidence, mismatch):
    license = "MIT" if mismatch else "Apache-2.0"
    (root / "service/example.rs").write_text(f"// SPDX-License-Identifier: {license}\n// Owned inert source.\n")
    audit.save(evidence, "expected-source", sources(root))


def inspect(root, evidence, stage):
    assert sources(root) == json.loads((evidence / "expected-source.json").read_text())
    values = audit.license_receipts(root)
    expected = {"matching": (1, 0, 0), "first": (2, 1, 0), "second": (3, 2, 0),
                "third": (4, 3, 0), "deferred": (4, 3, 1), "clean": (5, 3, 1),
                "exported": (5, 3, 1), "restarted": (5, 3, 1)}[stage]
    ledger = audit.counts(root)
    assert (len(values), ledger["finding_observations"], ledger["review_decisions"]) == expected
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
        ledger["stable_findings"] = db.execute("select count(*) from stable_findings").fetchone()[0]
    assert ledger["stable_findings"] == (0 if stage == "matching" else 1)
    mismatches, clean = inspect_receipts(root, values)
    assert len(mismatches) == min(3, expected[1])
    assert len({content for _, content in mismatches}) <= 1
    if expected[0] == 5:
        assert len(clean) == 2
        assert clean[0][1] == clean[1][1], "Identical source must retain its content identity"
        assert mismatches[0][1] != clean[0][1]
        initial = json.loads((evidence / "matching-check.json").read_text())["runIds"][0]
        later = next(run for run, _ in clean if run != initial)
        (evidence / "compare.txt").write_text(f"runs diff {mismatches[0][0]} {later}")
    if stage in ["exported", "restarted"]:
        audit.check_export(root, evidence)
    audit.save(evidence, stage + "-check", {"runIds": sorted(values), "completedScans": len(values),
        "matchingResults": len(clean), "mismatchResults": len(mismatches), "providerRequests": 0,
        "sourceExecuted": False, "sourceUnchangedByTools": True, "scriptedReviewControls": True, **ledger})


def inspect_receipts(root, values):
    mismatches, clean = [], []
    for run, value in values.items():
        assert value["status"] == "completed"
        data = value["data"]
        count = data.get("count", data.get("findingsCount"))
        assert count in [0, 1]
        observations = json.loads((root / ".kuzushi/v3/runs" / run / "findings.json").read_text())
        assert len(observations) == count
        if count:
            assert observations[0]["rule_id"] == "license-scan/spdx-header-mismatch"
            assert observations[0]["file_path"] == "service/example.rs"
            assert "apache-2.0" in observations[0]["message"]
            mismatches.append((run, data["treeHash"]))
        else:
            clean.append((run, data["treeHash"]))
        if "manifestsScanned" in data:
            assert data["manifestsScanned"] == 2
        scan = data["phaseStages"][0]["scan"]
        assert scan["engines"][0]["engine"] == "license-scan"
        assert scan["engines"][0]["outcome"] == "complete"
    return mismatches, clean


def wait_for_inspection(root, evidence, stage):
    deadline = time.monotonic() + 20
    while True:
        try:
            inspect(root, evidence, stage)
            return
        except (AssertionError, KeyError, FileNotFoundError, json.JSONDecodeError, sqlite3.OperationalError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.1)


root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
if stage == "prepare":
    prepare(root, evidence)
elif stage in ["mismatch", "match"]:
    edit_header(root, evidence, stage == "mismatch")
else:
    wait_for_inspection(root, evidence, stage)
