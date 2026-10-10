"""Owned citation-only module audit. All source files are inert comments."""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path


def native(root, evidence, tool, value, label):
    result = subprocess.run([os.environ["KUZUSHI_NATIVE_BIN"], "--target", str(root), "run", tool, "--input", "-"], input=json.dumps(value),text=True,capture_output=True,timeout=45)
    (evidence/(label+".stdout.json")).write_text(result.stdout)
    (evidence/(label+".stderr.txt")).write_text(result.stderr)
    assert result.returncode == 0,(label,result.stderr)
    return json.loads(result.stdout)


def rows(root):
    with sqlite3.connect((root/".kuzushi/v3/index.sqlite3").as_uri()+"?mode=ro",uri=True) as db:
        observations = [json.loads(row[0]) for row in db.execute("select finding_json from finding_observations where finding_json is not null order by created_seq")]
        audits = [json.loads(row[0]) for row in db.execute("select payload_json from audit_events where actor='findings:ground' order by seq")]
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        for table in ["investigation_work_attempts","investigation_call_reservations"]:
            if table in tables: assert db.execute("select count(*) from "+table).fetchone()[0] == 0
    assert not list((root/".kuzushi/v3/campaigns").glob("*/plan.json"))
    return observations,audits


def seed(root,evidence):
    for file in ["app.py","config.env"]: (root/file).unlink(missing_ok=True)
    ledger=[]
    for index in range(3):
        file = "citation-"+str(index)+".txt"
        (root/file).write_text("# Owned anchor "+str(index)+"\n")
        ledger.append({"file":file,"line":1,"title":"Labeled citation fixture "+str(index),"severity":"P3"})
    path=evidence/"ledger.jsonl"
    path.write_text("\n".join(json.dumps(row) for row in ledger)+"\n")
    imported=native(root,evidence,"workspace:import-findings",{"path":str(path),"tool":"owned-citation-fixture"},"import")
    assert imported["data"]["imported"]==3
    baseline=native(root,evidence,"findings:ground",{},"baseline")
    assert baseline["data"]["counts"]["grounded"]==3
    observations,audits=rows(root)
    assert len(observations)==3 and not audits
    (evidence/"before.json").write_text(json.dumps({"observations":observations,"baseline":baseline["data"]},indent=2)+"\n")
    (evidence/"ground-command.txt").write_text('run findings:ground {"maxBytesPerFile":64,"maxTotalBytes":1024}')
    (evidence/"import-command.txt").write_text("run workspace:import-findings "+json.dumps({"path":str(path),"tool":"owned-citation-fixture"}))
    (evidence/"seed-run-ids.json").write_text(json.dumps([p.parent.name for p in (root/".kuzushi/v3/runs").glob("*/result.json")]))


def verify(root,evidence,stage):
    before=json.loads((evidence/"before.json").read_text())
    observations,audits=rows(root)
    assert observations==before["observations"]
    seed_ids=set(json.loads((evidence/"seed-run-ids.json").read_text()))
    receipts=[json.loads(p.read_text()) for p in sorted((root/".kuzushi/v3/runs").glob("*/result.json")) if p.parent.name not in seed_ids]
    checks=[r["data"] for r in receipts if "inspections" in r.get("data",{})]
    if stage=="limited":
        assert any(c["checked"]==1 and c["coverage"]["hasMoreCandidates"] for c in checks)
        assert not audits
    elif stage in ["changed","repeat","recovered"]:
        matches=[c for c in checks if c["counts"].get("line_drift")==1 and c["counts"].get("file_missing")==1 and c["counts"].get("unavailable")==1]
        assert matches and len(audits)==2
        assert all(c["findingVerdictsChanged"] is False for c in matches)
        captured=next(i for i in matches[-1]["inspections"] if i["source"].get("file")=="citation-0.txt")["source"]["sha256"]
        assert captured=="sha256:"+hashlib.sha256((root/"citation-0.txt").read_bytes()).hexdigest()
        assert matches[-1]["coverage"]["reservedReadBytes"]<=1024
        if stage in ["repeat","recovered"]: assert len(matches)>=2 and matches[-1]["newlyDrifted"]==[]
    elif stage=="imported-again":
        assert len(observations)==3 and len(audits)==2
    (evidence/(stage+"-check.json")).write_text(json.dumps({"stage":stage,"originalObservationsUnchanged":True,"observations":len(observations),"citationAudits":len(audits),"providerReservations":0,"campaignPlans":0,"sourceExecuted":False},indent=2)+"\n")


def main():
    root,evidence,stage=Path(sys.argv[1]).resolve(),Path(sys.argv[2]).resolve(),sys.argv[3]
    if stage=="seed": seed(root,evidence)
    elif stage=="change-citations":
        (root/"citation-0.txt").write_text("# Different owned anchor\n")
        (root/"citation-1.txt").rename(evidence/"retained-citation-1.txt")
        (root/"citation-2.txt").write_text("# "+"x"*256+"\n")
    else: verify(root,evidence,stage)


if __name__=="__main__": main()
