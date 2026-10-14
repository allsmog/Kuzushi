"""Owned ledger lifecycle audit through native dispatch; no scanners or model work."""
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
from pathlib import Path


def native(root, evidence, label, tool, value, succeeds=True):
    result = subprocess.run([os.environ["KUZUSHI_NATIVE_BIN"], "--plain", "--target", str(root),
        "run", tool, "--input", json.dumps(value)], capture_output=True, text=True, timeout=30)
    (evidence / (label + ".stdout.json")).write_text(result.stdout)
    (evidence / (label + ".stderr.txt")).write_text(result.stderr)
    assert (result.returncode == 0) == succeeds, label + ": " + result.stderr
    return json.loads(result.stdout) if succeeds else result.stderr


def ledger_state(root):
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        return {table: db.execute("select count(*) from " + table).fetchone()[0] if table in tables else 0
            for table in ["finding_observations", "review_decisions", "investigation_call_reservations"]}


def sources(root):
    return {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in root.glob("*.rs")}


def exported(root, evidence, label):
    output = ".kuzushi/reports/" + label + ".json"
    native(root, evidence, label + "-export", "workspace:export-findings", {"output": output, "format": "json"})
    return json.loads((root / output).read_text())["findings"]


def seed(root, evidence):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    for name in ["a.rs", "b.rs"]:
        (root / name).write_text("// Labeled owned ledger audit. No executable fixture.\n")
    ledger = evidence / "owned-ledger.jsonl"
    ledger.write_text("\n".join(json.dumps({"file": name, "line": 1, "title": title, "severity": "info"})
        for name, title in [("a.rs", "Human dismissed observation"), ("b.rs", "Rule managed observation")]) + "\n")
    imported = native(root, evidence, "import", "workspace:import-findings", {"path": str(ledger), "tool": "owned-ledger"})
    assert imported["data"]["imported"] == 2
    original_report = native(root, evidence, "initial-report", "report:build", {})
    listed = native(root, evidence, "initial-list", "findings:list", {})["data"]
    human = next(row for row in listed["findings"] if row["file_path"] == "a.rs")
    native(root, evidence, "human-dismissal", "findings:dismiss", {
        "finding": human["fingerprint"], "reason": "false_positive", "note": "Owned manual decision retained"})
    page = native(root, evidence, "page-one", "findings:list", {"limit": 1})["data"]
    assert page["page"]["loaded"] == 1 and page["page"]["nextCursor"]
    second = native(root, evidence, "page-two", "findings:list", {"limit": 1, "cursor": page["page"]["nextCursor"]})["data"]
    assert second["page"]["loaded"] == 1 and second["findings"][0]["fingerprint"] != page["findings"][0]["fingerprint"]
    missing = native(root, evidence, "missing-id", "suppress:remove", {}, False)
    assert "id" in missing
    native(root, evidence, "unknown-option", "suppress:list", {"unexpected": True}, False)
    (evidence / "before.json").write_text(json.dumps({"sources": sources(root), "ledger": ledger_state(root),
        "importRun": imported["data"]["runId"], "reportSource": original_report["data"]["sourceRunId"]}, indent=2) + "\n")
    command = "run suppress:add " + json.dumps({"path": "b.rs", "reason": "false-positive",
        "statement": "Owned rule audit", "ruleId": "owned-rule", "days": 1})
    (evidence / "add-command.txt").write_text(command)


def check(root, evidence, stage):
    wait_for_shell_result(root, evidence, stage)
    before = json.loads((evidence / "before.json").read_text())
    assert sources(root) == before["sources"]
    assert ledger_state(root) == before["ledger"] == {
        "finding_observations": 2, "review_decisions": 1, "investigation_call_reservations": 0}
    listed = native(root, evidence, stage + "-list", "findings:list", {})["data"]["findings"]
    managed = next(row for row in listed if row["file_path"] == "b.rs")
    is_suppressed = stage in ["added", "readded", "listed"]
    assert managed.get("suppressed", False) == is_suppressed, stage
    rows = exported(root, evidence, stage)
    human = next(row for row in rows if row["location"]["file"] == "a.rs")
    assert human["reviewDecision"] == "rejected_false_positive"
    assert next(row for row in rows if row["location"]["file"] == "b.rs")["suppressed"] == is_suppressed
    report = native(root, evidence, stage + "-report", "report:build", {})
    assert report["data"]["sourceRunId"] == before["reportSource"], "Auxiliary work displaced the analysis source"
    (evidence / (stage + "-check.json")).write_text(json.dumps({"sourceUnchanged": True, "observations": 2,
        "humanDecisions": 1, "providerCalls": 0, "managedSuppressed": is_suppressed}, indent=2) + "\n")


def wait_for_shell_result(root, evidence, stage):
    expected = {"added": ("suppress:add", 1), "listed": ("suppress:list", 1),
        "removed": ("suppress:remove", 1), "readded": ("suppress:add", 2), "expired": ("suppress:list", 2)}
    if stage not in expected:
        return
    tool, count = expected[stage]
    for _ in range(100):
        paths = []
        for path in (root / ".kuzushi/v3/runs").glob("*/run.json"):
            value = json.loads(path.read_text())
            if value.get("tool") == tool and value.get("status") == "completed":
                paths.append(path)
        if len(paths) >= count:
            latest = max(paths, key=lambda path: path.stat().st_mtime_ns)
            result = json.loads((latest.parent / "result.json").read_text())
            (evidence / (stage + "-shell-result.json")).write_text(json.dumps(result, indent=2) + "\n")
            assert result["ok"] is True
            return
        time.sleep(0.1)
    raise AssertionError("Shell did not publish the expected completed " + tool + " receipt")


def expire(root):
    path = root / ".kuzushi/v3/suppressions.toml"
    body, replaced = re.subn(r"expires_at_unix = \d+", "expires_at_unix = 1", path.read_text())
    assert replaced == 1
    path.write_text(body)


root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
stage = sys.argv[3]
if stage == "seed":
    seed(root, evidence)
elif stage == "expire":
    expire(root)
else:
    check(root, evidence, stage)
