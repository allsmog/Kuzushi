"""Actual bounded IaC source checks on owned inert Dockerfiles. Never build them."""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from child_target_sources import native, read_ledger, save

LITERAL = "client\\scope/Dockerfile"
NESTED = "client/scope/Dockerfile"
SOURCE = {
    "README.md": "Owned IaC source identity fixture. No image build or source execution.\n",
    "Dockerfile": "FROM owned:1.0\nUSER nobody\n# Owned parent, never built.\n",
    NESTED: "FROM owned:latest\nUSER nobody\n# Owned nested directory, never built.\n",
    LITERAL: "FROM owned:latest\nUSER nobody\n# Owned literal directory, never built.\n",
}
OPTIONS = {"kind": "dockerfile", "maxEntries": 32, "maxFileBytes": 1024, "maxTotalBytes": 8192}


def sources(root):
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in SOURCE}


def prepare(root, evidence, home):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    for name, text in SOURCE.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    for directory in [root, home]:
        subprocess.run(["git", "init", "--quiet", "--initial-branch=main", str(directory)],
            capture_output=True, check=True, timeout=20)
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text("# Owned runtime-free IaC fixture. No model or credentials.\n")
    for name, target in [("nested", "client/scope"), ("literal", "client\\scope"), ("whole", ".")]:
        value = dict(OPTIONS, target=target)
        (evidence / ("run-" + name + ".txt")).write_text("run iac-scan:scan " + json.dumps(value))
    save(evidence, "source-before", sources(root))
    native(root, evidence, home, "iac-literal-seed", "iac-scan:scan", dict(OPTIONS, target="client\\scope"))
    inspect(root, evidence, "seeded")


def sast(root, evidence, home):
    for name, target in [("literal", "client\\scope"), ("nested", "client/scope")]:
        native(root, evidence, home, "iac-sast-" + name, "sast:scan", {
            "taskMode": "manual", "tasks": ["iac-scan"], "paths": [target],
            "triage": False, "verify": False, "autoPatch": False,
        })
    inspect(root, evidence, "sast")


def receipts(root):
    result = []
    for path in (root / ".kuzushi/v3/runs").glob("*/result.json"):
        value = json.loads(path.read_text())
        data = value.get("data", {})
        if value.get("output", "").startswith("iac-scan:") or data.get("engines") == ["iac-scan"]:
            assert value["status"] == "completed", value
            assert data["sourceCheckCurrent"] is True
            if "kind" in data:
                target = Path(data["target"])
                relative = target.relative_to(root).as_posix()
                expected = {name for name in SOURCE if Path(name).name == "Dockerfile"
                    and (target == root or (root / name).is_relative_to(target))}
                assert set(data["inspectedFiles"]) == expected
                scope = data["phaseStages"][0]["scan"]["scope"]
                assert scope["target"] == str(root)
                assert scope["paths"] == [relative]
                assert set(scope["inspectedFiles"]) == expected
            result.append((path.parent.name, data["snapshotHash"], data["treeHash"]))
    return result


def inspect(root, evidence, stage):
    assert sources(root) == json.loads((evidence / "source-before.json").read_text())
    expected = {"seeded": (1, 1, 1, 0), "direct": (3, 3, 2, 0), "sast": (5, 5, 2, 0),
        "whole": (6, 7, 2, 0), "reviewed": (6, 7, 2, 1),
        "exported": (6, 7, 2, 1), "restarted": (6, 7, 2, 1)}[stage]
    counts, rows = read_ledger(root)
    runs = receipts(root)
    assert (len(runs), counts["finding_observations"], counts["stable_findings"], counts["review_decisions"]) == expected
    latest, fingerprints = {}, {}
    for raw, storage in rows:
        finding = json.loads(raw)
        path = finding["file_path"]
        assert path in [LITERAL, NESTED]
        assert finding["rule_id"] == "iac-scan/dockerfile-floating-image"
        assert finding["staticProofState"] == "signal_only"
        assert finding["grounding"]["status"] == "grounded"
        assert storage and Path(storage).read_text() == SOURCE[path]
        latest[path] = finding
        fingerprints.setdefault(path, set()).add(finding["fingerprint"])
    assert all(len(values) == 1 for values in fingerprints.values())
    (evidence / "open-literal.txt").write_text("open generation:" + str(latest[LITERAL]["id"]))
    (evidence / "open-nested.txt").write_text("open generation:" + str(latest.get(NESTED, latest[LITERAL])["id"]))
    owners = set()
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
        for run, snapshot, tree in runs:
            row = db.execute("select tree_hash,workspace_root_fingerprint from target_snapshots where snapshot_hash=?", (snapshot,)).fetchone()
            assert row and row[0] == tree, run
            owners.add(row[1])
    assert len(owners) == 1 and len({row[2] for row in runs}) == 1
    for path in ["client", "client/scope", "client\\scope"]:
        assert not (root / path / ".kuzushi").exists()
    attempts = root / ".kuzushi/v3/workflow/phase-attempts.v2.jsonl"
    if attempts.exists():
        records = [json.loads(line)["record"] for line in attempts.read_text().splitlines()]
        assert all(row["event"] == "completed" and row["phase"] == "scan" for row in records)
        assert all(row["targetContentIdentity"]["kind"] == "indexed_snapshot" for row in records)
    if stage in ["exported", "restarted"]:
        reports = [json.loads(path.read_text()) for path in (root / ".kuzushi/reports").glob("*.json")]
        report = next(value for value in reports if value.get("count") == 2 and value.get("findings"))
        assert {row["location"]["file"] for row in report["findings"]} == {LITERAL, NESTED}
        assert {row["location"]["file"] for row in report["findings"]
            if row["reviewDecision"] == "deferred"} == {LITERAL}
        assert all(row["provenance"]["observationSource"]["blobHash"] for row in report["findings"])
    save(evidence, stage + "-check", {"actualNativeScans": len(runs), "observations": expected[1],
        "findings": expected[2], "decisions": expected[3], "sourceFilesChecked": len(SOURCE),
        "providerRequests": 0, "sourceExecuted": False, "sourceUnchanged": True,
        "literalAndNestedPathsDistinct": True, "allSnapshotOwnersAreParent": True,
        "acceptedMap": False, "acceptedScan": False, "runIds": sorted(row[0] for row in runs)})


def wait(root, evidence, stage):
    deadline = time.monotonic() + 20
    while True:
        try:
            inspect(root, evidence, stage)
            return
        except (AssertionError, FileNotFoundError, KeyError, json.JSONDecodeError, sqlite3.OperationalError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.1)


if __name__ == "__main__":
    root, evidence, home = (Path(value).resolve() for value in sys.argv[1:4])
    stage = sys.argv[4]
    if stage == "prepare":
        prepare(root, evidence, home)
    elif stage == "sast-run":
        sast(root, evidence, home)
    else:
        wait(root, evidence, stage)
