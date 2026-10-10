"""Owned labeled SHA history through native dispatch. No model or source execution."""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def environment(evidence):
    env = dict(os.environ, HOME=str(evidence / "home"))
    for key in ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "KUZUSHI_MODEL", "KUZUSHI_LANGGRAPH_BRIDGE", "NODE_OPTIONS"]:
        env.pop(key, None)
    return env


def native(root, evidence, name, tool, value, succeeds=True):
    result = subprocess.run([os.environ["KUZUSHI_NATIVE_BIN"], "--plain", "--target", str(root),
        "run", tool, "--input", json.dumps(value)], env=environment(evidence), capture_output=True, text=True, timeout=35)
    (evidence / (name + ".stderr.txt")).write_text(result.stderr)
    (evidence / (name + ".stdout.txt")).write_text(result.stdout)
    assert (result.returncode == 0) == succeeds, (name, result.stderr, result.stdout)
    value = json.loads(result.stdout)
    save(evidence, name, value)
    return value


def db_counts(root):
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        names = ["finding_observations", "review_decisions", "investigation_call_reservations", "investigation_work_attempts"]
        return {name:db.execute("select count(*) from " + name).fetchone()[0] if name in tables else 0 for name in names}


def comparison_input(root):
    fixture = json.loads((root / "fleet-fixture.json").read_text())
    assert fixture["revisionMetadataIsSynthetic"] and not fixture["sourceExecuted"]
    return {"target":"owned", "base":fixture["base"], "head":fixture["head"]}


def comparison(root, evidence, label):
    result = native(root, evidence, label, "fleet:diff-findings", comparison_input(root))
    entries = result["data"]["report"]["entries"]
    assert sorted(entry["presence"] for entry in entries) == ["base-only", "both", "head-only"]
    assert all(entry["fixStatus"] == "unassessed" and entry["matchBasis"] == "source-proximity-group" for entry in entries)
    assert "matches remain uncertain" in result["summary"]
    return entries


def seed(root, evidence, home):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    home.mkdir(parents=True, exist_ok=True)
    env = environment(evidence)
    env["KUZUSHI_FLEET_FIXTURE_ROOT"] = str(root)
    result = subprocess.run([os.environ["KUZUSHI_FLEET_TEST_BIN"], "--exact",
        "fleet::native_fixture::native_fleet_history_fixture_preserves_recorded_presence", "--nocapture"],
        env=env, capture_output=True, text=True, timeout=45)
    (evidence / "fixture-test.log").write_text(result.stdout + result.stderr)
    assert result.returncode == 0 and "1 passed" in result.stdout, result.stderr
    save(evidence, "source-before", {"sha256":hashlib.sha256((root / "package.json").read_bytes()).hexdigest(), "counts":db_counts(root)})


def before(root, evidence):
    native(root, evidence, "register", "fleet:register", {"id":"owned", "path":str(root), "label":"Owned labeled metadata"})
    again = native(root, evidence, "reregister", "fleet:register", {"id":"owned", "path":str(root), "label":"Owned policy history"})
    assert len(again["data"]["targets"]) == 1
    native(root, evidence, "blank-id", "fleet:register", {"id":" ", "path":str(root)}, False)
    ingest = native(root, evidence, "complete-ingest", "fleet:ingest", {})
    assert ingest["status"] == "completed" and ingest["data"]["report"]["rows"] == 3
    comparison(root, evidence, "comparison-before")
    native(root, evidence, "row-limit", "fleet:diff-findings", dict(comparison_input(root), maxRows=3), False)
    for label, value in [("zero-limit", {"limit":0}), ("excess-limit", {"limit":10001}), ("unknown-option", {"unknown":True})]:
        native(root, evidence, label, "fleet:findings", value, False)
    rows = native(root, evidence, "current-findings", "fleet:findings", {"limit":2})
    assert len(rows["data"]["findings"]) == 2
    status = native(root, evidence, "status-before", "fleet:status", {})
    assert status["data"]["report"]["corpusRows"] == 3
    corpus = evidence / "home/.kuzushi/v3/fleet/corpus.sqlite3"
    with sqlite3.connect(corpus) as db:
        db.execute("drop table corpus_history_targets")
    native(root, evidence, "legacy-comparison", "fleet:diff-findings", comparison_input(root), False)
    assert len(native(root, evidence, "legacy-current-reader", "fleet:findings", {})["data"]["findings"]) == 3
    missing = root / "owned-skipped"
    missing.mkdir()
    native(root, evidence, "register-skipped", "fleet:register", {"id":"skipped", "path":str(missing)})
    missing.rmdir()
    partial = native(root, evidence, "partial-ingest", "fleet:ingest", {}, False)
    assert partial["status"] == "partial" and len(partial["warnings"]) == 1
    assert "Skipped target: skipped:" in partial["summary"]
    native(root, evidence, "skipped-comparison", "fleet:diff-findings", dict(comparison_input(root), target="skipped"), False)
    entries = comparison(root, evidence, "comparison-after")
    save(evidence, "expected-comparison", entries)
    (evidence / "comparison-command.txt").write_text("run fleet:diff-findings " + json.dumps(comparison_input(root)))
    (evidence / "register-command.txt").write_text("run fleet:register " + json.dumps({"id":"owned", "path":str(root), "label":"Owned policy history"}))


def verify(root, evidence):
    original = json.loads((evidence / "source-before.json").read_text())
    assert hashlib.sha256((root / "package.json").read_bytes()).hexdigest() == original["sha256"]
    assert db_counts(root) == original["counts"] == {"finding_observations":4,"review_decisions":0,"investigation_call_reservations":0,"investigation_work_attempts":0}
    entries = comparison(root, evidence, "restart-comparison")
    assert entries == json.loads((evidence / "expected-comparison.json").read_text())
    with sqlite3.connect(evidence / "home/.kuzushi/v3/fleet/corpus.sqlite3") as db:
        assert db.execute("select count(*) from corpus_findings").fetchone()[0] == 3
        assert db.execute("select count(*) from corpus_observations").fetchone()[0] == 4
    coverage = root / ".kuzushi/v3/coverage.sqlite3"
    if coverage.exists():
        with sqlite3.connect(coverage) as db:
            assert db.execute("select count(*) from scan_baselines where phase='map'").fetchone()[0] == 0
    save(evidence, "verified", {"counts":db_counts(root),"revisionMetadataIsSynthetic":True,"sourceUnchanged":True,"fixVerdictsCreated":0})


root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
stage = sys.argv[3]
if stage == "seed":
    seed(root, evidence, Path(sys.argv[4]).resolve())
elif stage == "before":
    before(root, evidence)
else:
    verify(root, evidence)
