"""Compare new and authentic older scope-plan options without starting jobs."""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
LEGACY = REPO / "scripts/devex/artifacts/scope-context-variant-current-20261026/frozen/kuzushi"
LEGACY_SHA = "e8d38c732fc7ddc80cc0ac05c4f2d5386446f39b39a3ed1a1c56e24faf2ad87e"
SOURCE_LIST = REPO / "scripts/devex/artifacts/scope-context-variant-current-20261026/control/source-hashes.json"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(binary, root, evidence, home, label, tool, value):
    env = dict(os.environ, HOME=str(home))
    for name in ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "KUZUSHI_MODEL", "NODE_OPTIONS"]:
        env.pop(name, None)
    env["NODE_OPTIONS"] = "--import=" + str(REPO / "scripts/devex/fixtures/deny_provider_transport.mjs")
    env["KUZUSHI_TEST_DENIED_FETCH_LOG"] = str(evidence / "denied-fetch.jsonl")
    result = subprocess.run([str(binary), "--plain", "--target", str(root), "run", tool,
        "--input", json.dumps(value)], env=env, capture_output=True, text=True, timeout=90)
    (evidence / (label + "-stdout.json")).write_text(result.stdout)
    (evidence / (label + "-stderr.log")).write_text(result.stderr)
    assert result.returncode == 0, (result.stderr, result.stdout)
    return json.loads(result.stdout)["data"]


def prepare(root, evidence, home):
    assert sha(LEGACY) == LEGACY_SHA
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    names = json.loads(SOURCE_LIST.read_text())
    assert len(names) == 602
    for name in names:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        text = "{}\n" if path.suffix == ".json" else "# Owned inert filename fixture. Never executed.\n"
        path.write_text(text)
    for directory in [root, home]:
        subprocess.run(["git", "init", "--quiet", "--initial-branch=main", str(directory)],
            check=True, capture_output=True, timeout=20)
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('model = "openai-codex:gpt-6-luna"\n[runtime]\nthinking_level = "low"\n')
    current = Path(os.environ["KUZUSHI_NATIVE_BIN"])
    proposal = command(current, root, evidence, home, "inventory", "pack:scopes", {"operation":"create"})
    reference = proposal["reference"]
    for campaign, binary in [("sample-new", current), ("sample-legacy", LEGACY)]:
        value = {"campaignId":campaign, "investigationId":"filename-sample-test",
            "generationTool":"pack:suggest-scopes", "contextInput":{
                "proposalRef":reference,"threatModelRef":None,"thinkingLevel":"low"}}
        command(binary, root, evidence, home, campaign, "campaign:context-study", value)
    proof = {"source":{name:sha(root / name) for name in names},
        "config":sha(config), "plans":plan_hashes(root), "legacyBinarySha256":sha(LEGACY)}
    (evidence / "state-before.json").write_text(json.dumps(proof, indent=2) + "\n")
    verify(root, evidence, home, "prepared")


def plan_hashes(root):
    return {str(path.relative_to(root)):sha(path)
        for path in (root / ".kuzushi/v3/campaigns").glob("*/plan.json")}


def verify(root, evidence, home, stage):
    before = json.loads((evidence / "state-before.json").read_text())
    assert all(sha(root / name) == value for name, value in before["source"].items())
    assert sha(home / ".kuzushi/v3/config.toml") == before["config"]
    assert plan_hashes(root) == before["plans"] and len(before["plans"]) == 2
    state = root / ".kuzushi/v3"
    for campaign, selection in [("sample-new", "root-balanced-v1"), ("sample-legacy", None)]:
        plan = json.loads((state / "campaigns" / campaign / "plan.json").read_text())
        assert len(plan["jobs"]) == plan["workers"] == 1
        job = plan["jobs"][0]
        assert job["tool"] == "pack:suggest-scopes"
        assert job["input"].get("fileSelection") == selection
        assert "allowanceRef" not in job["input"]
    assert not list((state / "campaigns").glob("*/queue.json"))
    revisions = list((state / "scan-scopes/revisions").glob("*.json"))
    assert len(revisions) == 1 and json.loads(revisions[0].read_text()).get("acceptance") is None
    assert not (evidence / "denied-fetch.jsonl").exists()
    with sqlite3.connect((state / "index.sqlite3").as_uri() + "?mode=rw", uri=True) as db:
        db.execute("PRAGMA query_only=ON")
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        counts = {name:db.execute('select count(*) from "' + name + '"').fetchone()[0]
            for name in tables if name.startswith("investigation_") or name in ["finding_observations", "review_decisions"]}
        assert not any(counts.values()), counts
    for path in (state / "runs").glob("*/run.json"):
        record = json.loads(path.read_text())
        assert not record.get("llmCalls") and not record.get("llm_calls")
    if stage != "prepared":
        policy = next(evidence.glob("*-new-selection-policy.txt")).read_text()
        assert policy.count("Filename sample:") == 1
    if stage == "restarted":
        legacy = next(evidence.glob("*-preserved-legacy-policy.txt")).read_text()
        assert legacy.count("Filename sample:") == 1
    proof = {"sourceFilesUnchanged":602,"plansUnchanged":2,"newPolicy":"root-balanced-v1",
        "legacyPolicyOmitted":True,"jobsStarted":0,"modelRequests":0,
        "sourceExecuted":False,"acceptedScopes":0,"ledgerCounts":counts}
    (evidence / (stage + "-check.json")).write_text(json.dumps(proof, indent=2) + "\n")


if __name__ == "__main__":
    root, evidence, home = [Path(value).resolve() for value in sys.argv[1:4]]
    stage = sys.argv[4]
    prepare(root, evidence, home) if stage == "prepare" else verify(root, evidence, home, stage)
