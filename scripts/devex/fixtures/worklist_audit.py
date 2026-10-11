"""Owned inert context, advisory ranking and read-only coverage recovery."""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def source_hashes(root):
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in root.rglob("*.rs") if ".kuzushi" not in path.parts}


def prepare(root, evidence):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    paths = ["services/alpha/owned component/very-long-directory-name/src/settings.rs",
             "services/beta/src/settings.rs", "services/gamma/src/settings.rs", "child/src/child-settings.rs"]
    for name in paths:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("// Owned inert metadata fixture. Never built or executed.\n"
                        "pub fn argument_count() -> usize { std::env::args().count() }\n")
    save(evidence, "expected-source", source_hashes(root))


def child_context(root, evidence, home, binary):
    env = {key: value for key, value in os.environ.items() if key not in
           ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "KUZUSHI_MODEL", "KUZUSHI_LANGGRAPH_BRIDGE", "NODE_OPTIONS"]}
    env["HOME"] = str(home)
    for tool, value in [("context:build", '{"enrichment":false}'), ("worklist:rank", '{"limit":1}')]:
        result = subprocess.run([binary, "--target", str(root / "child"), "run", tool,
                                 "--input", value], env=env, capture_output=True, text=True, timeout=45)
        save(evidence, "child-cli-" + tool.split(":")[0],
             {"exit":result.returncode, "stdout":result.stdout, "stderr":result.stderr})
        assert result.returncode == 0, result.stderr
    rank = results(root / "child", "worklist:rank")[-1][1]
    assert rank["data"]["target"] == str(root / "child")
    assert rank["data"]["rankedTotal"] == len(rank["data"]["rows"]) == 1


def malformed(root, evidence):
    path = root / ".kuzushi/v3/coverage.sqlite3"
    assert not path.exists()
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE owned_sentinel(value TEXT)")
    save(evidence, "malformed-before", {"sha256":hashlib.sha256(path.read_bytes()).hexdigest()})


def repair(root, evidence):
    path = root / ".kuzushi/v3/coverage.sqlite3"
    before = json.loads((evidence / "malformed-before.json").read_text())["sha256"]
    assert hashlib.sha256(path.read_bytes()).hexdigest() == before
    with sqlite3.connect(path) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 0
        db.execute("CREATE TABLE scan_baselines(scope_id TEXT, phase TEXT, mode TEXT, run_id TEXT, "
                   "revision_sha TEXT, branch TEXT, dirty INTEGER, ts INTEGER, PRIMARY KEY(scope_id,phase,mode,ts))")
        db.execute("CREATE INDEX scan_baselines_latest ON scan_baselines(scope_id,phase,ts DESC)")
        db.execute("PRAGMA user_version=1")
    save(evidence, "explicit-fixture-repair", {"syntheticSetup":True, "modelCalls":0})


def results(root, tool):
    found = []
    for path in (root / ".kuzushi/v3/runs").glob("*/run.json"):
        summary = json.loads(path.read_text())
        if summary.get("tool") == tool:
            result_path = path.with_name("result.json")
            found.append((summary, json.loads(result_path.read_text()) if result_path.exists() else None))
    return sorted(found, key=lambda row: (row[0]["startedAtUnix"], row[0]["runId"]))


def inspect(root, evidence, stage):
    assert source_hashes(root) == json.loads((evidence / "expected-source.json").read_text())
    ranks = [value for _, value in results(root, "worklist:rank") if value and value.get("status") == "completed"]
    expected = {"capped":2, "child":4, "repaired":6, "restarted":6}
    assert len(ranks) == expected[stage], (stage, len(ranks))
    assert all(not value["data"]["sourceFreshnessVerified"] for value in ranks)
    assert any(value["data"]["target"] == str(root) and value["data"]["rankedTotal"] == 4
               and len(value["data"]["rows"]) == 1 for value in ranks), ranks
    if stage != "capped":
        child = [value for value in ranks if value["data"]["target"] == str(root / "child")]
        assert child and child[-1]["data"]["rows"][0]["path"] == "src/child-settings.rs", child
    if stage in ["repaired", "restarted"]:
        assert not ranks[-1]["data"]["degraded"], ranks[-1]
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        counts = {name:db.execute("select count(*) from " + name).fetchone()[0] if name in tables else 0
                  for name in ["finding_observations", "investigation_call_reservations", "investigation_work_attempts"]}
    assert all(value == 0 for value in counts.values()), counts
    save(evidence, stage + "-check", {"rankReceipts":len(ranks), "counts":counts, "source":source_hashes(root)})


root, evidence = map(Path, sys.argv[1:3])
root = root.resolve()
action = sys.argv[3]
actions = {"prepare":prepare, "malformed":malformed, "repair":repair}
if action == "child-context":
    child_context(root, evidence, Path(sys.argv[4]), sys.argv[5])
elif action in actions:
    actions[action](root, evidence)
else:
    inspect(root, evidence, action)
