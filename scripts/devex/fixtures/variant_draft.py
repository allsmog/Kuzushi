"""Owned current confirmation and one fully intercepted source-pattern draft."""
import hashlib
import json
import os
import shutil
import sqlite3
import sys
import time
from pathlib import Path
from reviewed_lessons import prepare
from rejected_context import execute

TOOL = "variant:lift-pattern"


def seed(root, evidence, home):
    prepare(root, evidence)
    repo = Path(__file__).resolve().parents[3]
    shutil.copyfile(repo / "scripts/devex/fixtures/variant_draft_provider.mjs", evidence / "provider.mjs")
    credential = home / ".kuzushi/pattern-credentials.json"
    credential.parent.mkdir(parents=True,exist_ok=True)
    credential.write_text(json.dumps({"openai-codex":{"access":"offline-pattern-fixture","expires":99999999999999}}))
    credential.chmod(0o600)
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True,exist_ok=True)
    native_dir = str(Path(os.environ["KUZUSHI_NATIVE_BIN"]).resolve().parent)
    command = ["env","PATH="+native_dir+os.pathsep+os.environ["PATH"],"node","--import",str(evidence / "provider.mjs"),str(repo / "scripts/langgraph-bridge.mjs")]
    config.write_text('model = "openai-codex:gpt-5.5"\n[runtime]\nthinking_level = "medium"\nlanggraph_bridge_command = '+json.dumps(command)+'\n[runtime.anthropic_oauth]\ncredentials_path = '+json.dumps(str(credential))+'\nallow_env_token = false\n')
    execute(root,home,evidence,"owned-approval","campaign:approve-allowance",{
        "investigationId":"owned-pattern","expectedRevision":0,"model":"openai-codex:gpt-5.5",
        "maxProviderCalls":2,"protectedReviewCalls":1,"reason":"Fully intercepted owned draft test"})
    (evidence / "command.txt").write_text("run "+TOOL+" "+json.dumps({"fingerprint":"F-0001",
        "allowanceRef":{"schemaVersion":1,"investigationId":"owned-pattern","revision":1,"workId":"pattern-1"}}))


def verify(root, evidence, stage):
    assert hashlib.sha256((root / "hello.txt").read_bytes()).hexdigest()==(evidence / "source-before.sha256").read_text()
    active = json.loads((evidence / "active-before.json").read_text())
    assert hashlib.sha256(Path(active["path"]).read_bytes()).hexdigest()==active["sha256"]
    calls = evidence / "pattern-calls.jsonl"
    if stage=="before":assert not calls.exists();return
    records = []
    deadline = time.monotonic()+20
    while time.monotonic()<deadline:
        records = [(p.parent,json.loads(p.read_text())) for p in (root / ".kuzushi/v3/runs").glob("*/run.json")]
        records = [(p,r) for p,r in records if r.get("tool")==TOOL]
        if len(records)==1 and records[0][1]["status"]!="running":break
        time.sleep(0.05)
    assert len(records)==1 and records[0][1]["status"]=="completed",records
    path,run = records[0]
    result = json.loads((path / "result.json").read_text())
    assert result["data"]["draft"] is True and result["data"]["accepted"] is False
    assert result["data"]["contextActivated"] is False and not run.get("phase")
    assert "Labeled synthetic source-pattern draft" in result["data"]["signature"]["description"]
    assert len(calls.read_text().splitlines())==1
    account = execute(root,Path(os.environ["HOME"]),evidence,"allowance-"+stage,
        "campaign:allowance",{"investigationId":"owned-pattern"})["allowance"]
    assert account["committedCalls"]==1 and account["reviewCalls"]==0
    assert account["limits"]["protectedReviewCalls"]==1
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri()+"?mode=rw",uri=True) as db:
        db.execute("PRAGMA query_only=ON")
        assert db.execute("select count(*) from finding_observations").fetchone()[0]==1
        assert db.execute("select count(*) from review_decisions").fetchone()[0]==1
    digest = hashlib.sha256((path / "result.json").read_bytes()).hexdigest()
    if stage=="draft":
        (evidence / "result.sha256").write_text(digest)
        (evidence / "replay.txt").write_text("replay "+run["runId"])
    else:assert digest==(evidence / "result.sha256").read_text()
    (evidence / (stage+"-check.json")).write_text(json.dumps({"toolRuns":1,"interceptedRequests":1,
        "liveProviderRequests":0,"sourceExecution":False,"activeContextUnchanged":True,
        "accepted":False,"phaseContinuation":False,"committedCalls":1,"protectedReviewCalls":1},indent=2)+"\n")


if __name__=="__main__":
    stage,root,evidence,*home = sys.argv[1:]
    root,evidence = Path(root).resolve(),Path(evidence).resolve()
    if stage=="seed":seed(root,evidence,Path(home[0]).resolve())
    else:verify(root,evidence,stage)
