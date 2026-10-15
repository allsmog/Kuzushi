"""Owned manifest inspection. No package installation or target execution."""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from secret_settings import ledger


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def native(root, evidence, name, tool, value, codes=(0,)):
    env = dict(os.environ, HOME=str(evidence / "home"))
    for key in ["NODE_OPTIONS", "KUZUSHI_MODEL", "KUZUSHI_LANGGRAPH_BRIDGE", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"]:
        env.pop(key, None)
    process = subprocess.run([os.environ["KUZUSHI_NATIVE_BIN"], "--plain", "--target", str(root),
        "run", tool, "--input", json.dumps(value)], env=env, capture_output=True, text=True, timeout=45)
    (evidence / (name + ".stdout.txt")).write_text(process.stdout)
    (evidence / (name + ".stderr.txt")).write_text(process.stderr)
    save(evidence, name + "-process", {"exitCode": process.returncode})
    assert process.returncode in codes, (name, process.stderr)
    result = json.loads(process.stdout) if process.stdout.strip() else None
    save(evidence, name, result)
    return result


def sources(root):
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.rglob("package.json") if ".kuzushi" not in path.parts}


def seed(root, evidence, home):
    assert not (evidence / "source-before.json").exists(), "Fixture already initialized"
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    for directory, text in [
        ("", '{"dependencies":{"root-example":"*"}}'),
        ("first", '{"dependencies":{"child-example":"latest"}}'),
        ("second", '{ malformed'),
        ("vendor", '{"dependencies":{"ignored-example":"*"}}'),
    ]:
        path = root / directory / "package.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n")
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('model = "openai-codex:gpt-5.5"\n[runtime]\nthinking_level = "medium"\n')
    assert home == (evidence / "home").resolve()
    save(evidence, "source-before", sources(root))
    scoped = native(root / "first", evidence, "scoped-cli", "dep-hygiene:check", {})
    assert scoped["status"] == "completed" and scoped["data"]["count"] == 1
    assert scoped["data"]["inspection"]["manifestsInspected"] == 1
    for name, options in [("exact-scope-refused", {"scanScopeRef": {}}),
        ("outside-refused", {"target": "../outside"})]:
        refusal = native(root, evidence, name, "dep-hygiene:check", options, (2, 3))
        assert refusal is None or refusal["status"] in ["blocked", "failed"]
    native(root, evidence, "context", "context:build", {"enrichment": False})
    (evidence / "scan-command.txt").write_text('run sast:scan ' + json.dumps({"taskMode": "manual",
        "tasks": ["dep-hygiene"], "triage": False, "verify": False, "autoPatch": False, "threatModelRef": None}))


def tool_results(root):
    return [json.loads(path.read_text()) for path in (root / ".kuzushi/v3/runs").glob("*/result.json")]


def verify(root, evidence, stage):
    assert sources(root) == json.loads((evidence / "source-before.json").read_text())
    results = tool_results(root)
    hygiene = [row for row in results if row.get("data", {}).get("inspection", {}).get("manifestsDiscovered") == 3]
    assert hygiene and all(row["status"] == "partial" for row in hygiene)
    for row in hygiene:
        data = row["data"]
        assert data["count"] == 2 and data["inspection"]["manifestsInspected"] == 2
        assert len(data["inspection"]["gaps"]) == 1 and "second/package.json" in data["inspection"]["gaps"][0]
        assert "invalid JSON document" in data["inspection"]["gaps"][0]
        assert len(data["snapshotHash"]) == 64 and len(data["treeHash"]) == 64
        assert all(finding["staticProofState"] == "signal_only" for finding in data["coreFindings"])
    if stage != "partial":
        sast = [row for row in results if row.get("data", {}).get("findingsCount") == 2]
        assert sast and sast[-1]["status"] == "partial"
        assert "invalid JSON document" in json.dumps(sast[-1])
    with ledger(root, evidence) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        names = ["finding_observations", "review_decisions", "investigation_call_reservations", "investigation_work_attempts"]
        counts = {name: db.execute("select count(*) from " + name).fetchone()[0] if name in tables else None for name in names}
    assert counts["investigation_call_reservations"] in [0, None]
    assert counts["investigation_work_attempts"] in [0, None]
    assert counts["finding_observations"] == (2 if stage == "partial" else 4), counts
    if stage in ["exported", "restarted"]:
        assert counts["review_decisions"] == 2
        report = json.loads((root / ".kuzushi/reports/findings.json").read_text())
        assert report["count"] == 2 and "Owned manifest policy requires owner review" in json.dumps(report)
        assert {row["location"]["file"] for row in report["findings"]} == {"package.json", "first/package.json"}
        assert "signal_only" in json.dumps(report)
    assert not list((root / ".kuzushi/v3/campaigns").glob("*/queue.json"))
    save(evidence, stage + "-verified", {"sourceUnchanged": True, "targetSourceExecuted": False,
        "providerRequests": 0, "counts": counts, "scriptedHumanDecisions": stage in ["exported", "restarted"]})


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    if sys.argv[3] == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    else:
        verify(root, evidence, sys.argv[3])
