"""Owned optional-assessment fixture with intercepted transport and no source execution."""
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path


INVESTIGATION = "owned-compliance"
MODEL = "openai-codex:gpt-5.5"


def save(folder, name, value):
    (folder / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def source_hashes(root):
    return {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.rglob("*") if path.is_file()
        and path.relative_to(root).parts[0] not in (".kuzushi", "owned-output")}


def prepare(root, evidence, home):
    repo = Path(__file__).resolve().parents[3]
    (root / "policy.py").write_text("# Owned policy marker. Never executed.\n")
    plugin = root / "owned-plugin"
    plugin.mkdir(exist_ok=True)
    (plugin / "README.md").write_text("Owned inert fixture metadata; no commands.\n")
    shutil.copyfile(repo / "scripts/devex/fixtures/compliance_provider.mjs", evidence / "provider.mjs")
    credentials = home / ".kuzushi/fixture-credentials.json"
    credentials.parent.mkdir(parents=True, exist_ok=True)
    credentials.write_text(json.dumps({"openai-codex":{"access":"fixture-placeholder","expires":99999999999999}}))
    credentials.chmod(0o600)
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    bridge = ["node", "--import", str(evidence / "provider.mjs"), str(repo / "scripts/langgraph-bridge.mjs")]
    config.write_text('model="' + MODEL + '"\n[runtime]\nthinking_level="medium"\nlanggraph_bridge_command=' + json.dumps(bridge)
        + '\n[runtime.anthropic_oauth]\ncredentials_path=' + json.dumps(str(credentials)) + '\nallow_env_token=false\n')
    inputs = {"pluginRoot":str(plugin),"outputDir":"owned-output"}
    (evidence / "unbound-command.txt").write_text("run shinsa:scan " + json.dumps(inputs))
    inputs["allowanceRef"] = {"schemaVersion":1,"investigationId":INVESTIGATION,"revision":1,"workId":"owned-assessment"}
    (evidence / "approved-command.txt").write_text("run shinsa:scan " + json.dumps(inputs))
    approval = {"investigationId":INVESTIGATION,"expectedRevision":0,"model":MODEL,
        "maxProviderCalls":2,"protectedReviewCalls":1,"reason":"One intercepted source-snippet assessment; zero live provider calls"}
    (evidence / "allowance-command.txt").write_text("run campaign:approve-allowance " + json.dumps(approval))
    (evidence / "status-command.txt").write_text("run campaign:allowance " + json.dumps({"investigationId":INVESTIGATION}))
    save(evidence, "source-before", {"source":source_hashes(root),
        "config":hashlib.sha256(config.read_bytes()).hexdigest(),"home":str(home)})


def verify(root, evidence, stage):
    expected = 0 if stage == "refused" else 1
    path = evidence / "compliance-calls.jsonl"
    calls = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
    assert len(calls) == expected, calls
    before = json.loads((evidence / "source-before.json").read_text())
    assert source_hashes(root) == before["source"]
    config = Path(before["home"]) / ".kuzushi/v3/config.toml"
    assert hashlib.sha256(config.read_bytes()).hexdigest() == before["config"]
    if not expected:
        assert not (root / "owned-output").exists()
    else:
        assert (root / "owned-output/shinsa-state.json").is_file()
        assert (root / "owned-output/compliance-report.md").is_file()
        with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=rw", uri=True) as db:
            db.execute("pragma query_only=on")
            assert db.execute("select count(*) from finding_observations").fetchone()[0] == 1
            assert db.execute("select count(*) from investigation_call_reservations").fetchone()[0] == 1
    assert not (root / ".kuzushi/v3/campaigns").exists()
    save(evidence, stage + "-check", {"interceptedRequests":expected,"liveProviderRequests":0,
        "sourceExecuted":False,"sourceAndModelUnchanged":True,"newJobs":0,"findingObservations":expected})


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "prepare":
        prepare(root, evidence, Path(sys.argv[4]).resolve())
    else:
        verify(root, evidence, stage)
