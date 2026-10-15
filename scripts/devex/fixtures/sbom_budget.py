"""Owned runtime-free dependency input allowance and recovery receipts."""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path


def save(evidence, label, value):
    (evidence / (label + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def sources(root):
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in ["package.json", "package-lock.json", "README.md"]}


def prepare(root, evidence):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    manifest = {"name": "owned-budget", "dependencies": {"owned-library": "^1.0"},
                "scripts": {"postinstall": "touch must-not-execute"}}
    lock = {"lockfileVersion": 3, "packages": {
        "": {"dependencies": manifest["dependencies"]},
        "node_modules/owned-library": {"version": "1.2.3"}}}
    (root / "package.json").write_text(json.dumps(manifest) + "\n")
    (root / "package-lock.json").write_text(json.dumps(lock) + "\n")
    (root / "README.md").write_text("Owned dependency input budget fixture. Source remains inert.\n")
    save(evidence, "source-before", sources(root))
    size = sum((root / name).stat().st_size for name in ["package.json", "package-lock.json"])
    (evidence / "recovery-command.txt").write_text(
        "run sbom-scan:scan " + json.dumps({"maxTotalBytes": size}) + "\n")
    result = subprocess.run([os.environ["KUZUSHI_NATIVE_BIN"], "tools", "--all", "--json"],
                            capture_output=True, text=True, timeout=30, check=True)
    descriptor = next(row for row in json.loads(result.stdout) if row["name"] == "sbom-scan:scan")
    assert descriptor["phase"] == "map", descriptor
    save(evidence, "descriptor", descriptor)


def no_investigation_work(root):
    index = root / ".kuzushi/v3/index.sqlite3"
    # SQLite may need to recreate WAL sidecars after the last writer closes.
    # Do not create a missing database; forbid SQL mutations on this connection.
    with sqlite3.connect(index.as_uri() + "?mode=rw", uri=True) as db:
        db.execute("pragma query_only = on")
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        for name in ["finding_observations", "review_decisions", "investigation_call_reservations",
                     "investigation_work_attempts"]:
            if name in tables:
                assert db.execute("select count(*) from " + name).fetchone()[0] == 0, name
    for name in ["phase-attempts.jsonl", "phase-attempts.v2.jsonl"]:
        path = root / ".kuzushi/workflow" / name
        assert not path.exists() or not path.read_text().strip(), name
    assert not (root / "must-not-execute").exists()


def inspect(root, evidence, stage):
    assert sources(root) == json.loads((evidence / "source-before.json").read_text())
    no_investigation_work(root)
    receipts = [json.loads(path.read_text()) for path in (root / ".kuzushi/v3/runs").glob("*/result.json")]
    failures = [row for row in receipts if row.get("status") == "failed"]
    completed = [row for row in receipts if row.get("status") == "completed"]
    assert len(failures) == 1, receipts
    failure = failures[0]
    assert "maxTotalBytes 2" in json.dumps(failure), failure
    assert failure["data"]["inspection"]["sourceBytesRead"] == 0, failure
    assert "components" not in failure["data"], failure
    assert len(completed) == (0 if stage == "failed" else 1), receipts
    for result in completed:
        inspect_completed(root, result)
    save(evidence, stage + "-check", {"failedRuns": len(failures), "completedRuns": len(completed),
         "sourceUnchanged": True, "sourceExecuted": False, "providerRequests": 0,
         "findings": 0, "phaseAttempts": 0, "discoveryJobs": 0})


def inspect_completed(root, result):
    data = result["data"]
    receipt = data["inspection"]
    size = sum((root / name).stat().st_size for name in ["package.json", "package-lock.json"])
    assert data["componentCount"] == 2, data
    assert {row["version"] for row in data["components"]} == {"^1.0", "1.2.3"}, data
    assert receipt["capturedFiles"] == 2, receipt
    for name in ["sourceBytesRead", "reservedSourceBytes", "capturedBytes"]:
        assert receipt[name] == size, receipt
    assert receipt["limits"]["maxTotalBytes"] == size, receipt
    for row in receipt["inputs"]:
        assert row["sha256"] == "sha256:" + hashlib.sha256((root / row["path"]).read_bytes()).hexdigest()
    lock = next(row for row in receipt["inputs"] if row["path"] == "package-lock.json")
    assert data["lockfiles"][0]["sha256"] == lock["sha256"], data
    assert "Source freshness and complete repository coverage remain unverified" in result["output"]


def inspect_pages(evidence, failure):
    pattern = "*-failure-recovery-page-*-40x12.txt" if failure else "*-recovered-details-page-*-40x12.txt"
    pages = sorted(evidence.glob(pattern))
    assert len(pages) == (16 if failure else 12), pages
    rows = []
    for path in pages:
        lines = path.read_text().splitlines()
        end = next(index for index, line in enumerate(lines) if line.startswith("⛭"))
        rows.extend(line for line in lines[3:end] if not line.strip().startswith("rows "))
    compact = "".join("".join(rows).split())
    expected = ["maxTotalBytes 2", "options sbom-scan:scan", "run sbom-scan:scan"] if failure else [
        "Source freshness is unverified", "declared ^1.0", "repo versions 1.2.3", "resolved 1.2.3"]
    for value in expected:
        assert "".join(value.split()) in compact, value
    save(evidence, "failure-pages" if failure else "component-pages", {"captures":len(pages),
         "textReachableThroughKeyboardPaging":True, "humanApproval":False})


root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
if stage == "prepare":
    prepare(root, evidence)
elif stage in ["failure-pages", "component-pages"]:
    inspect_pages(evidence, stage == "failure-pages")
else:
    inspect(root, evidence, stage)
