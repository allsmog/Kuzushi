"""Installed offline advisory checks over owned metadata. Never build target code."""
import hashlib
import json
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

from cargo_audit import LOCK, hashes
from child_target_sources import native, read_ledger, save

LITERAL = "client\\scope/Cargo.lock"
NESTED = "client/scope/Cargo.lock"
SOURCE = {
    "README.md": "Owned hypothetical dependency metadata. Runtime reachability is unassessed.\n",
    "Cargo.lock": '# Owned parent metadata. Never built.\nversion = 3\n\n[[package]]\nname = "owned-parent-fixture"\nversion = "0.0.0"\n',
    LITERAL: "# Owned literal directory.\n" + LOCK,
    NESTED: "# Owned nested directory.\n" + LOCK,
    "client\\scope/subpackage/Cargo.lock": "# Owned uninspected nested lockfile.\n" + LOCK,
}


def options(evidence):
    scanner = json.loads((evidence / "scanner.json").read_text())
    return {"binary": scanner["binary"], "advisoryDb": scanner["advisoryDb"],
        "offline": True, "allowStale": True, "timeoutMs": 30000, "maxLockfileBytes": 4096}


def prepare(root, evidence, home):
    binary = shutil.which("cargo-audit")
    assert binary, "Installed standalone cargo-audit is required"
    database = evidence / "advisory-db"
    cache = Path.home() / ".cargo/advisory-db"
    assert cache.is_dir(), "Use an existing local database; no fetch is permitted"
    shutil.copytree(cache, database, ignore=shutil.ignore_patterns("*.lock"))
    save(evidence, "scanner", {"binary": binary,
        "binarySha256": hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
        "version": subprocess.check_output([binary, "--version"], text=True).strip(),
        "advisoryDb": str(database), "databaseSourceHashes": hashes(database)})
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
    config.write_text("# Owned runtime-free offline advisory fixture. No model or credentials.\n")
    for name, target in [("nested", "client/scope"), ("literal", "client\\scope"), ("root", ".")]:
        (evidence / ("run-" + name + ".txt")).write_text(
            "run cargo-audit:scan " + json.dumps(dict(options(evidence), target=target)))
    save(evidence, "source-before", hashes(root))
    native(root, evidence, home, "cargo-literal-seed", "cargo-audit:scan",
        dict(options(evidence), target="client\\scope"))
    inspect(root, evidence, "seeded")


def sast(root, evidence, home):
    declared = {"cargoAudit" + key[0].upper() + key[1:]: value
        for key, value in options(evidence).items()}
    for name, target in [("literal", "client\\scope"), ("nested", "client/scope")]:
        native(root, evidence, home, "cargo-sast-" + name, "sast:scan", dict(declared,
            taskMode="manual", tasks=["cargo-audit"], paths=[target],
            triage=False, verify=False, autoPatch=False))
    inspect(root, evidence, "sast")


def receipts(root):
    runs = []
    for path in (root / ".kuzushi/v3/runs").glob("*/result.json"):
        value = json.loads(path.read_text())
        data = value.get("data", {})
        direct = value.get("output", "").startswith("cargo-audit:")
        if not direct and data.get("engines") != ["cargo-audit"]:
            continue
        assert value["status"] == "completed", value
        assert data["sourceCheckCurrent"] is True
        assert data["nativeInspections"][0]["offline"] is True
        if direct:
            selected = Path(data["target"]).relative_to(root)
            file = (selected / "Cargo.lock").as_posix()
            scope = data["phaseStages"][0]["scan"]["scope"]
            assert scope == {"target": str(root), "paths": [file], "inspectedFiles": [file]}
            assert data["count"] == (0 if file == "Cargo.lock" else 1)
            engine = data["phaseStages"][0]["scan"]["engines"][0]
            assert "ruleIds" not in engine and "Advisory policy was not recorded" in engine["detail"]
        runs.append((path.parent.name, data["snapshotHash"], data["treeHash"]))
    return runs


def inspect(root, evidence, stage):
    assert hashes(root) == json.loads((evidence / "source-before.json").read_text())
    scanner = json.loads((evidence / "scanner.json").read_text())
    assert hashes(Path(scanner["advisoryDb"])) == scanner["databaseSourceHashes"]
    assert hashlib.sha256(Path(scanner["binary"]).read_bytes()).hexdigest() == scanner["binarySha256"]
    expected = {"seeded": (1, 1, 1, 0), "direct": (3, 3, 2, 0), "sast": (5, 5, 2, 0),
        "root": (6, 5, 2, 0), "reviewed": (6, 5, 2, 1), "source-read": (6, 5, 2, 1),
        "exported": (6, 5, 2, 1), "restarted": (6, 5, 2, 1)}[stage]
    counts, rows = read_ledger(root)
    runs = receipts(root)
    assert (len(runs), counts["finding_observations"], counts["stable_findings"], counts["review_decisions"]) == expected
    latest, identities = {}, {}
    for raw, storage in rows:
        finding = json.loads(raw)
        file = finding["file_path"]
        assert file in [LITERAL, NESTED]
        assert finding["rule_id"] == "RUSTSEC-2020-0071"
        assert finding["start_line"] == 6
        assert finding["staticProofState"] == "signal_only"
        assert finding["grounding"]["status"] == "grounded"
        assert storage and Path(storage).read_text() == SOURCE[file]
        latest[file] = finding
        identities.setdefault(file, set()).add(finding["fingerprint"])
    assert all(len(values) == 1 for values in identities.values())
    for name, file in [("literal", LITERAL), ("nested", NESTED)]:
        (evidence / ("open-" + name + ".txt")).write_text(
            "open generation:" + str(latest.get(file, latest[LITERAL])["id"]))
    owners = set()
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
        assert all(row[0] == "open" for row in db.execute("select current_status from stable_findings"))
        for run, snapshot, tree in runs:
            row = db.execute("select tree_hash,workspace_root_fingerprint from target_snapshots where snapshot_hash=?", (snapshot,)).fetchone()
            assert row and row[0] == tree, run
            owners.add(row[1])
    assert len(owners) == 1 and len({row[2] for row in runs}) == 1
    for file in ["client", "client/scope", "client\\scope", "client\\scope/subpackage"]:
        assert not (root / file / ".kuzushi").exists()
    attempts = root / ".kuzushi/v3/workflow/phase-attempts.v2.jsonl"
    if attempts.exists():
        records = [json.loads(line)["record"] for line in attempts.read_text().splitlines()]
        assert all(row["event"] == "completed" and row["phase"] == "scan" for row in records)
        assert all(row["targetContentIdentity"]["kind"] == "indexed_snapshot" for row in records)
    if stage == "source-read":
        pages = "\n".join(path.read_text() for path in sorted(evidence.glob("*literal-page-*.txt")))
        assert 'name = "time"' in pages and 'version = "0.1.40"' in pages
    if stage in ["exported", "restarted"]:
        reports = [json.loads(path.read_text()) for path in (root / ".kuzushi/reports").glob("*.json")]
        report = next(value for value in reports if value.get("count") == 2 and value.get("findings"))
        assert {row["location"]["file"] for row in report["findings"]} == {LITERAL, NESTED}
        assert all(row["location"]["startLine"] == 6 for row in report["findings"])
        assert {row["location"]["file"] for row in report["findings"]
            if row["reviewDecision"] == "deferred"} == {LITERAL}
        assert all(row["provenance"]["observationSource"]["blobHash"] for row in report["findings"])
    save(evidence, stage + "-check", {"actualModuleScans": len(runs), "observations": expected[1],
        "findings": expected[2], "decisions": expected[3], "sourceFilesChecked": len(SOURCE),
        "providerRequests": 0, "sourceExecuted": False, "sourceUnchanged": True,
        "databaseUnchanged": True, "literalAndNestedPathsDistinct": True,
        "allSnapshotOwnersAreParent": True, "childFindingsRemainOpen": True,
        "acceptedMap": False, "acceptedScan": False})


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
    root, evidence, home = (Path(value).resolve() for value in sys.argv[1:4])
    stage = sys.argv[4]
    if stage == "prepare":
        prepare(root, evidence, home)
    elif stage == "sast-run":
        sast(root, evidence, home)
    else:
        wait(root, evidence, stage)
