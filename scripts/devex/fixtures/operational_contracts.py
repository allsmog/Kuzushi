"""Owned operational metadata audit. No models, scanners or target-code execution."""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path


TOOLS = ["config:show", "router:show", "workspace:status", "threat-model:methodologies", "engagement:aim"]


def native(root, evidence, label, arguments):
    command = [os.environ["KUZUSHI_NATIVE_BIN"], "--target", str(root), *arguments]
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    (evidence / (label + ".stdout.json")).write_text(result.stdout)
    (evidence / (label + ".stderr.txt")).write_text(result.stderr)
    assert result.returncode == 0, label + ": " + result.stderr
    return json.loads(result.stdout)


def prepare(root, evidence, home):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "hello.txt").write_text("Owned operational inspection fixture. Never executed.\n")
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('model = "openai-codex:gpt-5.5"\n[runtime]\nthinking_level = "medium"\n')
    baseline = {"source": hashlib.sha256((root / "hello.txt").read_bytes()).hexdigest(),
                "config": hashlib.sha256(config.read_bytes()).hexdigest(), "home": str(home)}
    (evidence / "baseline.json").write_text(json.dumps(baseline, indent=2) + "\n")
    catalog = native(root, evidence, "catalog-all", ["tools", "--all", "--json"])
    default = native(root, evidence, "catalog-default", ["tools", "--json"])
    indexed = {tool["name"]: tool for tool in catalog}
    assert indexed["engagement:aim"]["maturity"] == "compatibility"
    assert "engagement:aim" not in {tool["name"] for tool in default}
    for name in TOOLS:
        assert indexed[name]["phase"] == "operate", name
    outputs = inspect_tools(root, evidence)
    (evidence / "catalog-check.json").write_text(json.dumps({"visibleTools": len(catalog),
        "defaultTools": len(default), "exactDispatchRetained": True, "tools": TOOLS,
        "legacyDefaultRemoved": True, "providerRequests": 0}, indent=2) + "\n")
    assert outputs["workspace:status"]["data"]["active"] is True
    verify(root, evidence, "prepared")


def inspect_tools(root, evidence):
    inputs = {"router:show": {"MODEL_TRIAGE_ESCALATION": "openai-codex:gpt-6-luna"},
              "engagement:aim": {"focus": "evidence handling", "engines": ["context:build"], "budgetUsd": 2.5}}
    outputs = {}
    for name in TOOLS:
        outputs[name] = native(root, evidence, name.replace(":", "-"),
                               ["run", name, "--input", json.dumps(inputs.get(name, {}))])
        assert outputs[name]["status"] == "completed", name
    assert outputs["config:show"]["data"]["model"] == "openai-codex:gpt-5.5"
    assert outputs["config:show"]["data"]["config"]["runtime"]["thinking_level"] == "medium"
    role = next(row for row in outputs["router:show"]["data"]["roles"] if row["role"] == "triage_escalation")
    assert role["effective"] == "openai-codex:gpt-6-luna"
    assert "operator override" in outputs["router:show"]["output"]
    compatibility = outputs["engagement:aim"]["data"]["compatibility"]
    assert compatibility == {"budgetEnforced": False, "workApproved": False, "replacementTool": "campaign:study"}
    return outputs


def verify_database(root):
    database = root / ".kuzushi/v3/index.sqlite3"
    if not database.is_file():
        return {"databasePresent": False}
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        for table in ["finding_observations", "review_decisions", "investigation_call_reservations", "investigation_work_attempts"]:
            if table in tables:
                assert db.execute("select count(*) from " + table).fetchone()[0] == 0, table
    return {"databasePresent": True, "observations": 0, "decisions": 0, "providerReservations": 0, "workAttempts": 0}


def verify(root, evidence, stage):
    baseline = json.loads((evidence / "baseline.json").read_text())
    assert hashlib.sha256((root / "hello.txt").read_bytes()).hexdigest() == baseline["source"]
    config = Path(baseline["home"]) / ".kuzushi/v3/config.toml"
    assert hashlib.sha256(config.read_bytes()).hexdigest() == baseline["config"]
    assert (root / "engagement/harness.toml").is_file()
    assert not (root / ".kuzushi/v3/campaigns").exists()
    assert not (root / ".kuzushi/threat-model.json").exists()
    result = {"stage": stage, "sourceUnchanged": True, "operatorConfigurationUnchanged": True,
              "legacyMetadataExists": True, "approvedWorkCreated": False,
              "providerRequests": 0, "scannerJobs": 0, "sourceExecuted": False, **verify_database(root)}
    (evidence / (stage + "-check.json")).write_text(json.dumps(result, indent=2) + "\n")


root, evidence = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
if sys.argv[3] == "prepare":
    prepare(root, evidence, Path(sys.argv[4]).resolve())
else:
    verify(root, evidence, sys.argv[3])
