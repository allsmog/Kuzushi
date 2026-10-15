"""Current confirmed owned metadata and one completely intercepted hypothesis."""
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from variant_draft import seed as draft_seed
from rejected_context import execute

TOOL = "triage:chain-hunt"


def seed(root,evidence,home):
    draft_seed(root,evidence,home)
    environment=dict(os.environ,KUZUSHI_CHAIN_FIXTURE_ROOT=str(root))
    result=subprocess.run([os.environ["KUZUSHI_CHAIN_TEST_BIN"],"--exact",
        "modules::registry::chain_hunt_contract_tests::prepare_native_chain_hypothesis_fixture","--nocapture"],
        env=environment,capture_output=True,text=True,timeout=30,check=True)
    (evidence / "chain-preparation.log").write_text(result.stdout+result.stderr)
    receipt=json.loads((root / ".kuzushi/chain-fixture.json").read_text())
    assert receipt["findingsAreSynthetic"] and receipt["providerRequests"]==0
    (evidence / "members.json").write_text(json.dumps(receipt["memberFingerprints"]))
    (evidence / "second-before.sha256").write_text(hashlib.sha256((root / "second.txt").read_bytes()).hexdigest())
    shutil.copyfile(Path(__file__).with_name("chain_hypotheses_provider.mjs"),evidence / "provider.mjs")
    (evidence / "command.txt").write_text("run "+TOOL+" "+json.dumps({
        "allowanceRef":{"schemaVersion":1,"investigationId":"owned-pattern","revision":1,"workId":"hypothesis-1"}}))


def verify(root,evidence,stage):
    assert hashlib.sha256((root / "hello.txt").read_bytes()).hexdigest()==(evidence / "source-before.sha256").read_text()
    assert hashlib.sha256((root / "second.txt").read_bytes()).hexdigest()==(evidence / "second-before.sha256").read_text()
    active=json.loads((evidence / "active-before.json").read_text())
    assert hashlib.sha256(Path(active["path"]).read_bytes()).hexdigest()==active["sha256"]
    calls=evidence / "hypothesis-calls.jsonl"
    if stage=="before":assert not calls.exists();return
    records=[];deadline=time.monotonic()+20
    while time.monotonic()<deadline:
        records=[(p.parent,json.loads(p.read_text())) for p in (root / ".kuzushi/v3/runs").glob("*/run.json")]
        records=[(p,r) for p,r in records if r.get("tool")==TOOL]
        if len(records)==1 and records[0][1]["status"]!="running":break
        time.sleep(.05)
    assert len(records)==1 and records[0][1]["status"]=="completed",records
    path,run=records[0];data=json.loads((path / "result.json").read_text())["data"]
    assert data["hypotheses"] is True and data["relationshipsVerified"] is False
    assert data["sourceRevisionVerified"] is False and not run.get("phase")
    assert data["confirmedCount"]==2 and len(data["chains"])==1
    assert len(calls.read_text().splitlines())==1
    account=execute(root,Path(os.environ["HOME"]),evidence,"allowance-"+stage,"campaign:allowance",{"investigationId":"owned-pattern"})["allowance"]
    assert account["committedCalls"]==1 and account["reviewCalls"]==0 and account["limits"]["protectedReviewCalls"]==1
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri()+"?mode=rw",uri=True) as db:
        db.execute("PRAGMA query_only=ON")
        assert db.execute("select count(*) from finding_observations").fetchone()[0]==3
        assert db.execute("select count(*) from review_decisions").fetchone()[0]==2
    listed=subprocess.run([os.environ["KUZUSHI_NATIVE_BIN"],"--target",str(root),"findings","--json"],
        capture_output=True,text=True,timeout=15,check=True)
    rows=json.loads(listed.stdout)
    if isinstance(rows,dict):rows=rows["findings"]
    hypothesis=next(row for row in rows if row["tool"]=="chains")
    (evidence / "open-hypothesis.txt").write_text("open "+hypothesis["fingerprint"])
    digest=hashlib.sha256((path / "result.json").read_bytes()).hexdigest()
    if stage=="result":
        (evidence / "result.sha256").write_text(digest);(evidence / "replay.txt").write_text("replay "+run["runId"])
    else:assert digest==(evidence / "result.sha256").read_text()
    (evidence / (stage+"-check.json")).write_text(json.dumps({"interceptedRequests":1,"liveRequests":0,
        "sourceExecution":False,"activeContextUnchanged":True,"observations":3,"humanDecisions":2,
        "relationshipsVerified":False,"phaseContinuation":False,"committedCalls":1,"protectedReviewCalls":1},indent=2)+"\n")


if __name__=="__main__":
    stage,root,evidence,*home=sys.argv[1:];root,evidence=Path(root).resolve(),Path(evidence).resolve()
    if stage=="seed":seed(root,evidence,Path(home[0]).resolve())
    else:verify(root,evidence,stage)
