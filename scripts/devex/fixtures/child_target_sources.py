"""Owned child-target scans retain workspace paths and the actual cited bytes."""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def child_bytes(name):
    return (json.dumps({"name": name, "dependencies": {"owned-example": "*"},
        "scripts": {"postinstall": "touch must-not-execute"}}, separators=(",", ":")) + "\n").encode()


def secret_bytes(name):
    return ("# Owned " + name + " documentation example. Never executed.\n"
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n").encode()


def sources(root):
    names = ["package.json", "LICENSE", "config.env", "client/package.json",
        "service/package.json", "client/config.env", "service/config.env"]
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in names}


def native(root, evidence, home, label, tool, value):
    environment = dict(os.environ, HOME=str(home), KUZUSHI_SKIP_ONBOARDING="1")
    for name in ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "KUZUSHI_MODEL", "KUZUSHI_LANGGRAPH_BRIDGE", "NODE_OPTIONS"]:
        environment.pop(name, None)
    command = [os.environ["KUZUSHI_NATIVE_BIN"], "--target", str(root), "run", tool,
               "--run-id", label, "--input", json.dumps(value)]
    result = subprocess.run(command, cwd=evidence, env=environment, text=True,
        capture_output=True, timeout=90, check=False)
    (evidence / (label + "-stdout.json")).write_text(result.stdout)
    (evidence / (label + "-stderr.log")).write_text(result.stderr)
    assert result.returncode == 0, (command, result.stderr, result.stdout)
    assert json.loads(result.stdout)["status"] == "completed"


def prepare(root, evidence, home):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    subprocess.run(["git", "init", "--quiet", "--initial-branch=main", str(home)],
        capture_output=True, check=True, timeout=20)
    (home / ".kuzushi/v3").mkdir(parents=True, exist_ok=True)
    (home / ".kuzushi/v3/config.toml").write_text("# Owned runtime-free child-target fixture.\n")
    (root / "package.json").write_text('{"name":"parent","license":"MIT"}\n')
    (root / "LICENSE").write_text("Owned inert text.\n")
    (root / "config.env").write_bytes(secret_bytes("parent"))
    for name in ["client", "service"]:
        (root / name).mkdir()
        (root / name / "package.json").write_bytes(child_bytes(name))
        (root / name / "config.env").write_bytes(secret_bytes(name))
    save(evidence, "expected-source", sources(root))
    native(root, evidence, home, "child-license-client", "license-scan:scan", {"target": "client"})
    inspect(root, evidence, "seeded")


def sast(root, evidence, home):
    for engine in ["license-scan", "dep-hygiene", "secret-scan"]:
        native(root, evidence, home, "child-sast-" + engine, "sast:scan", {
            "taskMode": "manual", "tasks": [engine], "paths": ["client"],
            "triage": False, "verify": False, "autoPatch": False,
        })
    inspect(root, evidence, "sast")


def scanner_results(root):
    results = []
    for path in (root / ".kuzushi/v3/runs").glob("*/result.json"):
        value = json.loads(path.read_text())
        data = value.get("data", {})
        if "manifestsScanned" in data or value.get("output", "").startswith(("dep-hygiene:", "secret-scan:")) or data.get("engines") in [["license-scan"], ["dep-hygiene"], ["secret-scan"]]:
            assert value["status"] == "completed", value
            assert len(data["coreFindings"]) == 1
            assert data["coreFindings"][0]["file_path"] in [
                "client/package.json", "service/package.json", "client/config.env", "service/config.env"]
            results.append(path.parent.name)
    return sorted(results)


def read_ledger(root):
    path = root / ".kuzushi/v3/index.sqlite3"
    with sqlite3.connect(path.as_uri() + "?mode=rw", uri=True) as db:
        db.execute("PRAGMA query_only=ON")
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        counts = {name: db.execute("select count(*) from " + name).fetchone()[0] if name in tables else 0
            for name in ["stable_findings", "finding_observations", "review_decisions", "investigation_call_reservations", "investigation_work_attempts"]}
        rows = db.execute("select o.finding_json,b.storage_path from finding_observations o left join blobs b on b.blob_hash=o.blob_hash order by o.created_seq").fetchall()
    assert counts["investigation_call_reservations"] == counts["investigation_work_attempts"] == 0
    return counts, rows


def inspect(root, evidence, stage):
    assert sources(root) == json.loads((evidence / "expected-source.json").read_text())
    expected = {"seeded": (1, 1, 0), "six": (6, 6, 0), "sast": (9, 6, 0),
                "reviewed": (9, 6, 1), "exported": (9, 6, 1), "restarted": (9, 6, 1)}[stage]
    counts, rows = read_ledger(root)
    runs = scanner_results(root)
    assert (len(runs), counts["stable_findings"], counts["review_decisions"]) == expected
    assert counts["finding_observations"] == len(runs)
    latest, fingerprints = {}, {}
    for raw, storage in rows:
        finding = json.loads(raw)
        path = finding["file_path"]
        assert path in ["client/package.json", "service/package.json", "client/config.env", "service/config.env"]
        name, file = path.split("/")
        expected_source = secret_bytes(name) if file == "config.env" else child_bytes(name)
        assert storage and Path(storage).read_bytes() == expected_source
        assert finding["grounding"]["status"] == "grounded"
        key = (finding["rule_id"], path)
        latest[key] = finding
        fingerprints.setdefault(key, set()).add(finding["fingerprint"])
    assert len(latest) == expected[1]
    assert all(len(values) == 1 for key, values in fingerprints.items() if not key[0].startswith("secret-scan/"))
    selected = latest[("license-scan/missing-license", "client/package.json")]
    (evidence / "open-client.txt").write_text("open generation:" + str(selected["id"]))
    for directory in [root, root / "client", root / "service"]:
        assert not (directory / "must-not-execute").exists()
    if stage in ["exported", "restarted"]:
        check_report(root, evidence)
    save(evidence, stage + "-check", {"runIds": runs, "actualLocalScans": len(runs),
        "sourceBytesMatchSelectedChild": True, "sameSourceIdentityStable": True,
        "opaqueSecretProducerAliasesPreserved": True,
        "providerRequests": 0, "sourceExecuted": False, "scriptedReviewControls": True, **counts})


def check_report(root, evidence):
    documents = []
    for path in (root / ".kuzushi/reports").glob("*.json"):
        value = json.loads(path.read_text())
        if value.get("count") == 6 and value.get("findings"):
            documents.append((path, value))
    assert documents
    path, value = documents[-1]
    assert {row["location"]["file"] for row in value["findings"]} == {
        "client/package.json", "service/package.json", "client/config.env", "service/config.env"}
    assert sum(row["reviewDecision"] == "deferred" for row in value["findings"]) == 1
    assert all(row["provenance"]["observationSource"]["blobHash"] for row in value["findings"])
    save(evidence, "report-check", {"path": str(path), "findings": 6,
        "decisions": 1, "pathsAreWorkspaceRelative": True})


def wait_for_inspection(root, evidence, stage):
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
        wait_for_inspection(root, evidence, stage)
