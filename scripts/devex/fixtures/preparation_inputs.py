"""Owned dependency failures and frozen engine inputs; never dispatch scan jobs."""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

CAMPAIGN = "owned-engine-inputs"


def sources(root):
    return {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in root.glob("*.rs")}


def environment(home, evidence):
    return {**os.environ, "HOME": str(home), "PATH": str(evidence / "bin") + os.pathsep + os.environ["PATH"]}


def native(root, home, evidence, label, tool, value, success=True):
    started = time.monotonic()
    result = subprocess.run([os.environ["KUZUSHI_NATIVE_BIN"], "--plain", "--target", str(root),
        "run", tool, "--input", json.dumps(value)], env=environment(home, evidence),
        capture_output=True, text=True, timeout=35)
    (evidence / (label + ".stdout.json")).write_text(result.stdout)
    (evidence / (label + ".stderr.txt")).write_text(result.stderr)
    assert (result.returncode == 0) == success, result.stderr
    return json.loads(result.stdout)["data"] if success else {"error": result.stderr, "elapsed": time.monotonic() - started}


def seed(root, evidence, home):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "main.rs").write_text("// Owned comparison input, not executable source.\n")
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('model = "openai-codex:gpt-5.5"\n[runtime]\nthinking_level = "medium"\n')
    binaries = evidence / "bin"
    binaries.mkdir()
    cargo = binaries / "cargo-audit"
    cargo.write_text("#!/bin/sh\n# Owned stalled dependency fixture.\nsleep 20\n")
    cargo.chmod(0o700)
    semgrep = binaries / "operator-semgrep"
    semgrep.write_text("#!/bin/sh\n# Owned metadata-only fixture, not executed.\nexit 0\n")
    semgrep.chmod(0o700)
    plan = {"campaignId": "must-not-publish", "scanInput": {"taskMode": "auto", "threatModelRef": None,
        "scanContextRef": None, "triage": False, "verify": False, "autoPatch": False}}
    refused = native(root, home, evidence, "stalled-probe", "campaign:study", plan, False)
    assert "Dependency inspection failed" in refused["error"] and refused["elapsed"] < 8
    (evidence / "before.json").write_text(json.dumps({"sources": sources(root), "home": str(home)}))


def no_work(root, evidence, label):
    before = json.loads((evidence / "before.json").read_text())
    assert sources(root) == before["sources"]
    assert not list((root / ".kuzushi/v3/campaigns").glob("*/queue.json"))
    if label in ["probe-refused", "cache-refused"]:
        assert not list((root / ".kuzushi/v3/campaigns").glob("*/plan.json")), "Preparation failure published a plan"
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        for table in ["investigation_call_reservations", "investigation_work_attempts", "finding_observations"]:
            if table in tables:
                assert db.execute("select count(*) from " + table).fetchone()[0] == 0, table
    if label == "inspected":
        for size in ["40x12", "60x20", "80x24"]:
            pages = sorted(evidence.glob("*engine-source*" + size + ".txt"))
            text = " ".join(" ".join(path.read_text().split()) for path in pages)
            for value in ["RECORDED ENGINE INPUTS", "semgrep: located at", "Recorded content", "Current inspection limits"]:
                assert value in text, size + ": " + value
            assert len({path.read_text() for path in pages}) > 1, size + ": no actual paging"
    (evidence / (label + "-check.json")).write_text(json.dumps({"sourceUnchanged": True,
        "providerRequests": 0, "scanJobsStarted": 0, "findings": 0}, indent=2) + "\n")


def oversized_cache(root, evidence):
    cargo = evidence / "bin/cargo-audit"
    cargo.write_text("#!/bin/sh\n# Owned successful dependency probe.\nprintf '%s\\n' 'owned-version-1'\n")
    cache = root / ".kuzushi/cpg-rs"
    cache.mkdir(parents=True, exist_ok=True)
    with (cache / "oversized.graph").open("wb") as stream:
        stream.truncate(128 * 1024 * 1024 + 1)


def frozen(root, evidence):
    before = json.loads((evidence / "before.json").read_text())
    binary = evidence / "bin/operator-semgrep"
    result = native(root, Path(before["home"]), evidence, "frozen-plan", "campaign:study", {
        "campaignId": CAMPAIGN, "scanInput": {"taskMode": "manual", "tasks": ["semgrep"],
            "semgrepBinary": str(binary), "threatModelRef": None, "scanContextRef": None}})
    executables = result["equivalence"]["components"]["engineIdentity"]["requestedSelection"]["executables"]
    assert len(executables) == 1 and executables[0]["path"] == str(binary.resolve())
    digest = "sha256:" + hashlib.sha256(binary.read_bytes()).hexdigest()
    assert executables[0]["sha256"] == digest
    (evidence / "frozen-evidence.json").write_text(json.dumps({"binary": str(binary), "digest": digest,
        "planSha256": result["planSha256"], "jobs": result["jobCount"]}, indent=2) + "\n")
    no_work(root, evidence, "frozen")


def main():
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    stage = sys.argv[3]
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    elif stage == "oversized":
        oversized_cache(root, evidence)
    elif stage == "frozen":
        frozen(root, evidence)
    else:
        no_work(root, evidence, stage)


if __name__ == "__main__":
    main()
