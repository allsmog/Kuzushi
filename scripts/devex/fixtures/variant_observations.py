"""One explicitly allowed, fully intercepted source-only related-observation job."""
import hashlib
import json
import os
import shutil
import sqlite3
import sys
import time
from pathlib import Path
from variant_draft import seed as draft_seed
from rejected_context import execute

TOOL = "variant:hunt"


def seed(root, evidence, home):
    draft_seed(root,evidence,home)
    repo = Path(__file__).resolve().parents[3]
    shutil.copyfile(repo / "scripts/devex/fixtures/variant_observations_provider.mjs",evidence / "provider.mjs")
    (root / "related.txt").write_text("Owned related greeting. Never executed.\n")
    (evidence / "related-before.sha256").write_text(hashlib.sha256((root / "related.txt").read_bytes()).hexdigest())
    (evidence / "command.txt").write_text("run "+TOOL+" "+json.dumps({"fingerprint":"F-0001","includeVendored":False,
        "allowanceRef":{"schemaVersion":1,"investigationId":"owned-pattern","revision":1,"workId":"related-1"}}))


def verify(root, evidence, stage):
    assert hashlib.sha256((root / "hello.txt").read_bytes()).hexdigest()==(evidence / "source-before.sha256").read_text()
    assert hashlib.sha256((root / "related.txt").read_bytes()).hexdigest()==(evidence / "related-before.sha256").read_text()
    active=json.loads((evidence / "active-before.json").read_text())
    assert hashlib.sha256(Path(active["path"]).read_bytes()).hexdigest()==active["sha256"]
    calls=evidence / "variant-calls.jsonl"
    if stage=="before":assert not calls.exists();return
    records=[];deadline=time.monotonic()+20
    while time.monotonic()<deadline:
        records=[(p.parent,json.loads(p.read_text())) for p in (root / ".kuzushi/v3/runs").glob("*/run.json")]
        records=[(p,r) for p,r in records if r.get("tool")==TOOL]
        if len(records)==1 and records[0][1]["status"]!="running":break
        time.sleep(0.05)
    assert len(records)==1 and records[0][1]["status"]=="partial",records
    path,run=records[0];result=json.loads((path / "result.json").read_text())
    assert result["data"]["coverage"]=={"complete":False,"sourceRevisionVerified":False}
    assert not run.get("phase") and len(result["data"]["variants"])==1
    assert result["data"]["variants"][0]["file_path"]=="related.txt"
    assert len(calls.read_text().splitlines())==1
    account=execute(root,Path(os.environ["HOME"]),evidence,"allowance-"+stage,"campaign:allowance",{"investigationId":"owned-pattern"})["allowance"]
    assert account["committedCalls"]==1 and account["reviewCalls"]==0
    assert account["limits"]["protectedReviewCalls"]==1
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri()+"?mode=rw",uri=True) as db:
        db.execute("PRAGMA query_only=ON")
        assert db.execute("select count(*) from finding_observations").fetchone()[0]==2
        assert db.execute("select count(*) from review_decisions").fetchone()[0]==1
    digest=hashlib.sha256((path / "result.json").read_bytes()).hexdigest()
    if stage=="result":
        (evidence / "result.sha256").write_text(digest)
        (evidence / "replay.txt").write_text("replay "+run["runId"])
        (evidence / "open-related.txt").write_text("open "+result["data"]["variants"][0]["fingerprint"])
    else:assert digest==(evidence / "result.sha256").read_text()
    (evidence / (stage+"-check.json")).write_text(json.dumps({"toolRuns":1,"interceptedRequests":1,"liveProviderRequests":0,
        "sourceExecution":False,"activeContextUnchanged":True,"phaseContinuation":False,
        "observations":2,"humanDecisions":1,"coverageVerified":False,"committedCalls":1,"protectedReviewCalls":1},indent=2)+"\n")


if __name__=="__main__":
    stage,root,evidence,*home=sys.argv[1:]
    root,evidence=Path(root).resolve(),Path(evidence).resolve()
    if stage=="seed":seed(root,evidence,Path(home[0]).resolve())
    else:verify(root,evidence,stage)
