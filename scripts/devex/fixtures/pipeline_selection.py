"""Owned class-selection fixture. Intercepted provider, no source execution."""
import hashlib
import json
import shutil
import sqlite3
import sys
from pathlib import Path


MODEL = "openai-codex:gpt-5.5"


def save(folder, name, value):
    (folder / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def source_hashes(root):
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in root.rglob("*") if p.is_file() and p.relative_to(root).parts[0] != ".kuzushi"}


def prepare(root, evidence, home):
    repo = Path(__file__).resolve().parents[3]
    (root / "owned.py").write_text("# Owned source marker; never executed.\n")
    shutil.copyfile(repo / "scripts/devex/fixtures/pipeline_selection_provider.mjs", evidence / "provider.mjs")
    credentials = home / ".kuzushi/fixture-credentials.json"
    credentials.parent.mkdir(parents=True, exist_ok=True)
    credentials.write_text(json.dumps({"openai-codex":{"access":"fixture-placeholder","expires":99999999999999}}))
    credentials.chmod(0o600)
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    bridge = ["node", "--import", str(evidence / "provider.mjs"), str(repo / "scripts/langgraph-bridge.mjs")]
    config.write_text('model="' + MODEL + '"\n[runtime]\nthinking_level="medium"\nlanggraph_bridge_command=' + json.dumps(bridge)
        + '\n[runtime.anthropic_oauth]\ncredentials_path=' + json.dumps(str(credentials)) + '\nallow_env_token=false\n')
    approval = {"investigationId":"owned-selection","expectedRevision":0,"model":MODEL,
        "maxProviderCalls":2,"protectedReviewCalls":1,"reason":"One intercepted class proposal; no scan work or live calls"}
    allowance = {"schemaVersion":1,"investigationId":"owned-selection","revision":1,"workId":"one-selection"}
    for name, command in {
        "approve":"run campaign:approve-allowance " + json.dumps(approval),
        "select":"run pipeline:taint-cwe-select " + json.dumps({"allowanceRef":allowance}),
        "status":"run campaign:allowance " + json.dumps({"investigationId":"owned-selection"}),
    }.items():
        (evidence / (name + "-command.txt")).write_text(command)
    save(evidence, "before", {"source":source_hashes(root),"config":hashlib.sha256(config.read_bytes()).hexdigest(),"home":str(home)})


def verify(root, evidence, stage):
    expected = 0 if stage in ["unbound", "supplied"] else 1
    path = evidence / "selection-calls.jsonl"
    calls = path.read_text().splitlines() if path.exists() else []
    assert len(calls) == expected
    before = json.loads((evidence / "before.json").read_text())
    assert source_hashes(root) == before["source"]
    config = Path(before["home"]) / ".kuzushi/v3/config.toml"
    assert hashlib.sha256(config.read_bytes()).hexdigest() == before["config"]
    if expected:
        with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=rw", uri=True) as db:
            db.execute("pragma query_only=on")
            assert db.execute("select count(*) from investigation_call_reservations").fetchone()[0] == 1
            assert db.execute("select count(*) from finding_observations").fetchone()[0] == 0
            call, review, settled = db.execute("select call_json, review, settled_at from investigation_call_reservations").fetchone()
            assert json.loads(call)["work"] == "scope" and review == 0 and settled is not None
    assert not (root / ".kuzushi/v3/campaigns").exists()
    save(evidence, stage + "-check", {"interceptedRequests":expected,"liveProviderRequests":0,
        "sourceExecuted":False,"sourceAndModelUnchanged":True,"newCampaignJobs":0,"findingObservations":0})


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "prepare":
        prepare(root, evidence, Path(sys.argv[4]).resolve())
    else:
        verify(root, evidence, stage)
