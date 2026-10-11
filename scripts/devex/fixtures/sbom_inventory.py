"""Owned dependency inventory lifecycle. Package scripts remain inert."""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def source_identity(root):
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in ["package.json", "package-lock.json", "README.md"]}


def write_packages(root, major):
    name = "owned-library"
    manifest = {"name": "owned-inventory", "dependencies": {name: f"^{major}.0"},
                "scripts": {"postinstall": "touch must-not-execute"}}
    packages = {"": {"dependencies": manifest["dependencies"]},
                "node_modules/" + name: {"version": f"{major}.2.3"}}
    (root / "package.json").write_text(json.dumps(manifest) + "\n")
    (root / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": packages}) + "\n")


def prepare(root, evidence):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "README.md").write_text("Owned dependency inventory fixture. Package scripts are never executed.\n")
    write_packages(root, 1)
    (root / "package.json").write_text("{owned invalid manifest}\n")
    save(evidence, "expected-source", source_identity(root))
    command = [os.environ["KUZUSHI_NATIVE_BIN"], "tools", "--all", "--json"]
    result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=True)
    descriptor = next(tool for tool in json.loads(result.stdout) if tool["name"] == "sbom-scan:scan")
    assert descriptor["phase"] == "map", descriptor
    save(evidence, "descriptor", descriptor)


def change_source(root, evidence, action):
    if action == "corrupt":
        (root / "package.json").write_text("{owned invalid manifest}\n")
    else:
        write_packages(root, 2 if action == "revise" else 1)
    save(evidence, "expected-source", source_identity(root))


def no_investigation_work(root):
    index = root / ".kuzushi/v3/index.sqlite3"
    with sqlite3.connect(index.as_uri() + "?mode=ro", uri=True) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        for name in ["finding_observations", "review_decisions", "investigation_call_reservations", "investigation_work_attempts"]:
            if name in tables:
                assert db.execute("select count(*) from " + name).fetchone()[0] == 0, name
    for name in ["phase-attempts.jsonl", "phase-attempts.v2.jsonl"]:
        path = root / ".kuzushi/workflow" / name
        assert not path.exists() or not path.read_text().strip(), name
    assert not (root / "must-not-execute").exists()


def inspect_receipts(root, evidence, stage):
    assert source_identity(root) == json.loads((evidence / "expected-source.json").read_text())
    no_investigation_work(root)
    receipts = {path.parent.name: json.loads(path.read_text())
                for path in (root / ".kuzushi/v3/runs").glob("*/result.json")}
    completed = [value for value in receipts.values() if value.get("status") == "completed"]
    failures = [value for value in receipts.values() if value.get("status") == "failed"]
    expected = {"repaired": (1, 0), "revised": (2, 0), "failed": (2, 1), "recovered": (3, 1), "restarted": (3, 1)}
    assert (len(completed), len(failures)) == expected[stage], receipts
    check_completed(completed)
    for value in failures:
        assert "parse package.json" in json.dumps(value), value
        assert "components" not in value.get("data", {}), value
    save(evidence, stage + "-check", {"completedInventoryRuns": len(completed), "failedRuns": len(failures),
         "sourceUnchangedByTools": True, "packageScriptsExecuted": False, "providerRequests": 0,
         "phaseAttempts": 0, "findings": 0, "discoveryJobs": 0, "realExecutorReceipts": sorted(receipts)})


def check_completed(completed):
    versions = set()
    for value in completed:
        data = value["data"]
        assert data["manifestsScanned"] == 1 and data["lockfileCount"] == 1
        assert data["cycloneDx"]["bomFormat"] == "CycloneDX"
        assert data["spdx"]["spdxVersion"] == "SPDX-2.3"
        assert data["dependencies"]
        versions.update(item["version"] for item in data["components"] if item["name"] == "owned-library")
    assert {"^1.0", "1.2.3"} <= versions
    if len(completed) > 1:
        assert {"^2.0", "2.2.3"} <= versions


def inspect_pages(evidence):
    captures = sorted(evidence.glob("*-components-page-*-40x12.txt"))
    assert len(captures) == 12, "Missing narrow keyboard-page captures"
    pages = []
    for path in captures:
        lines = path.read_text().splitlines()
        end = next(index for index, line in enumerate(lines) if line.startswith("⛭"))
        pages.extend(line for line in lines[3:end] if not line.strip().startswith("rows "))
    text = "".join("".join(pages).split())
    for value in ["Source freshness is unverified.", "declared ^2.0", "repo versions 2.2.3", "resolved 2.2.3"]:
        assert "".join(value.split()) in text, (value, pages)
    save(evidence, "narrow-pages-check", {"capturedPages": len(captures), "completeVersionAndFreshnessText": True})


def inspect_failure_pages(evidence):
    captures = sorted(evidence.glob("*-failure-page-*-40x12.txt"))
    assert len(captures) == 6, "Missing narrow failure pages"
    rows = []
    for path in captures:
        lines = path.read_text().splitlines()
        end = next(index for index, line in enumerate(lines) if line.startswith("⛭"))
        rows.extend(line for line in lines[3:end] if not line.strip().startswith("rows "))
        assert "ERROR" in path.read_text(), "Error badge must remain visible"
    text = "".join("".join(rows).split())
    for value in ["Component inventory failed", "key must be a string at line 1 column 2", "run sbom-scan:scan"]:
        assert "".join(value.split()) in text, (value, rows)
    save(evidence, "narrow-failure-check", {"capturedPages": len(captures), "fullCauseAndRecoveryReadable": True})


root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
if stage == "prepare":
    prepare(root, evidence)
elif stage in ["repair", "revise", "corrupt"]:
    change_source(root, evidence, stage)
elif stage == "pages":
    inspect_pages(evidence)
elif stage == "failure-pages":
    inspect_failure_pages(evidence)
else:
    inspect_receipts(root, evidence, stage)
