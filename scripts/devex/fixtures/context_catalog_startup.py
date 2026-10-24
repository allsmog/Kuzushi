"""Owned startup controls. Runtime-free inspection; source is never executed."""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from ndiff_metadata import no_analysis_work


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def native(root, evidence, name, arguments):
    result = subprocess.run(
        [os.environ["KUZUSHI_NATIVE_BIN"], "--plain", "--target", str(root), *arguments],
        capture_output=True, text=True, timeout=30,
    )
    (evidence / (name + ".stdout.json")).write_text(result.stdout)
    (evidence / (name + ".stderr.txt")).write_text(result.stderr)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def prepare(root, evidence):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "owned.rs").write_text("// Owned source comments. Never compiled or executed.\n")
    save(evidence, "source-before", hashlib.sha256((root / "owned.rs").read_bytes()).hexdigest())


def verify(root, evidence, stage):
    expected = json.loads((evidence / "source-before.json").read_text())
    assert hashlib.sha256((root / "owned.rs").read_bytes()).hexdigest() == expected
    assert not (root / ".kuzushi/threat-model.json").exists()
    assert not list((root / ".kuzushi/v3/campaigns").glob("*/plan.json"))
    rows = [json.loads(p.read_text()) for p in (root / ".kuzushi/v3/runs").glob("*/run.json")]
    assert all(row["status"] == "completed" and not row.get("model") for row in rows)
    expected_tools = [] if stage == "fresh" else ["threat-model:models"]
    if stage in ["indexed", "restarted"]:
        expected_tools.append("context:build")
        assert (root / ".kuzushi/context-snapshot.json").exists()
    assert sorted(row["tool"] for row in rows) == sorted(expected_tools), rows
    save(evidence, stage + "-check", {
        "tools": expected_tools, "sourceUnchanged": True,
        "providerRequests": 0, "sourceExecuted": False,
        "phaseAttempts": 0, "accounting": no_analysis_work(root),
    })


def catalog(root, evidence):
    result = native(root, evidence, "empty-context-catalog", ["run", "threat-model:models", "--input", "{}"])
    assert result["data"]["models"] == [] and result["data"]["active"] is None
    verify(root, evidence, "catalog")


def index(root, evidence):
    native(root, evidence, "repository-context", ["run", "context:build", "--input", '{"enrichment":false}'])
    verify(root, evidence, "indexed")


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    stage = sys.argv[3]
    if stage == "prepare":
        prepare(root, evidence)
    elif stage == "catalog":
        catalog(root, evidence)
    elif stage == "index":
        index(root, evidence)
    else:
        verify(root, evidence, stage)
