"""Owned labeled stored reports. No generation, model requests or source execution."""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def hashes(root):
    paths = [root / "main.rs", *sorted((root / "x-ray").glob("*"))]
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}


def native(root, evidence, name, value, succeeds=True):
    env = dict(os.environ, HOME=str(evidence / "home"))
    for key in ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "KUZUSHI_MODEL", "KUZUSHI_LANGGRAPH_BRIDGE", "NODE_OPTIONS"]:
        env.pop(key, None)
    result = subprocess.run([os.environ["KUZUSHI_NATIVE_BIN"], "--plain", "--target", str(root),
        "run", "x-ray:read", "--input", json.dumps(value)], env=env, capture_output=True, text=True, timeout=35)
    (evidence / (name + ".stderr.txt")).write_text(result.stderr)
    (evidence / (name + ".stdout.txt")).write_text(result.stdout)
    assert (result.returncode == 0) == succeeds, (name, result.stderr)
    output = json.loads(result.stdout)
    save(evidence, name, output)
    return output


def seed(root, evidence, home):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "main.rs").write_text("// Owned inert metadata; never compiled or executed.\n")
    (root / "x-ray").mkdir()
    values = {"x-ray.md":"# Owned labeled report\n## X-Ray Verdict\nREADY\nThis manually supplied fixture describes inert metadata. The tier is an unassessed stored claim.\n",
        "entry-points.md":"# Entry Points\n> Owned metadata | 1 entry point | 1 permissionless | 0 role-gated | 0 admin-only\n",
        "invariants.md":"# Invariants\n### G-1 Retain the declared package name\n",
        "architecture.svg":"<svg xmlns=\"http://www.w3.org/2000/svg\"><title>Owned labeled metadata</title></svg>\n"}
    for name, body in values.items():
        (root / "x-ray" / name).write_text(body)
    home.mkdir(parents=True, exist_ok=True)
    save(evidence, "before", {"hashes":hashes(root),"reportIsManuallySupplied":True})


def check_result(value):
    assert value["status"] == "completed"
    assert value["data"]["costUsdExact"] is False
    assert value["data"]["readProvenance"]["generationSpend"] == "unknown"
    assert value["data"]["readProvenance"]["sourceFreshness"] == "not-assessed"
    assert value["data"]["readProvenance"]["readerProviderCalls"] == 0
    assert value["data"]["readProvenance"]["architectureContentValidated"] is False
    assert value["data"]["verdict"]["tier"] == "READY"
    assert value["data"]["entryPointCounts"]["total"] == value["data"]["invariantCounts"]["total"] == 1
    assert "Recorded report tier" in value["summary"] and value["warnings"]


def before(root, evidence):
    check_result(native(root, evidence, "headless-read", {}))
    check_result(native(root, evidence, "explicit-target", {"target":str(root)}))
    native(root, evidence, "unknown-option", {"unknown":True}, False)
    path = root / "x-ray/architecture.svg"
    original = path.read_bytes()
    with path.open("r+b") as stream:
        stream.truncate(8 * 1024 * 1024 + 1)
    native(root, evidence, "oversized-architecture", {}, False)
    path.write_bytes(original)
    missing = root / "x-ray/invariants.md"
    original = missing.read_bytes()
    missing.unlink()
    native(root, evidence, "missing-required", {}, False)
    missing.write_bytes(original)
    save(evidence, "prepared-check", {"hashes":hashes(root),"readerCalls":0,"generationSpendKnown":False})


def broken(root, evidence):
    path = root / "x-ray/invariants.md"
    (evidence / "original-invariants.md").write_bytes(path.read_bytes())
    path.unlink()


def restore(root, evidence):
    path = root / "x-ray/invariants.md"
    assert not path.exists()
    path.write_bytes((evidence / "original-invariants.md").read_bytes())
    assert hashes(root) == json.loads((evidence / "before.json").read_text())["hashes"]


def verify(root, evidence):
    assert hashes(root) == json.loads((evidence / "before.json").read_text())["hashes"]
    check_result(native(root, evidence, "restart-read", {}))
    index = root / ".kuzushi/v3/index.sqlite3"
    counts = {}
    if index.exists():
        with sqlite3.connect(index.as_uri() + "?mode=ro", uri=True) as db:
            tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
            for name in ["finding_observations", "review_decisions", "investigation_call_reservations", "investigation_work_attempts"]:
                counts[name] = db.execute("select count(*) from " + name).fetchone()[0] if name in tables else 0
    assert all(value == 0 for value in counts.values()), counts
    coverage = root / ".kuzushi/v3/coverage.sqlite3"
    if coverage.exists():
        with sqlite3.connect(coverage) as db:
            assert db.execute("select count(*) from scan_baselines where phase='map'").fetchone()[0] == 0
    save(evidence, "verified", {"hashes":hashes(root),"counts":counts,"acceptedMapCreated":False,
        "reportIsManuallySupplied":True,"providerRequests":0,"sourceExecuted":False})


root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
stage = sys.argv[3]
if stage == "seed":
    seed(root, evidence, Path(sys.argv[4]).resolve())
elif stage == "before":
    before(root, evidence)
elif stage == "broken":
    broken(root, evidence)
elif stage == "restore":
    restore(root, evidence)
else:
    verify(root, evidence)
