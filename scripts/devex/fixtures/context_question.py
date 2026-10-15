"""Finite question approval and one synthetic native request over owned static source."""
import hashlib
import json
import shutil
import sys
import time
from pathlib import Path
import map_functionality
from secret_settings import ledger


def save(folder, name, value):
    (folder/(name+".json")).write_text(json.dumps(value,indent=2)+"\n")


def seed(root, evidence, home):
    config = home/".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True,exist_ok=True)
    provider=evidence/"context-question-provider.mjs"
    shutil.copyfile(Path(__file__).with_name("context_question_provider.mjs"),provider)
    credentials=home/".kuzushi/offline-oauth.json"
    credentials.write_text('{"openai-codex":{"access":"offline-fixture","expires":99999999999999}}')
    repo=Path(__file__).resolve().parents[3]
    config.write_text('model = "openai-codex:gpt-5.5"\n[runtime]\nthinking_level = "medium"\nlanggraph_bridge_command = '+json.dumps(["node","--import",str(provider),str(repo/"scripts/langgraph-bridge.mjs")])+'\n[runtime.anthropic_oauth]\ncredentials_path = '+json.dumps(str(credentials))+'\nallow_env_token = false\n')
    (root/"app.py").write_text(map_functionality.SOURCE)
    map_functionality.execute(root,evidence,home,"context","context:build",{"enrichment":False})
    map_functionality.execute(root,evidence,home,"entry-points","entry-points:extract",{})
    mapped=map_functionality.execute(root,evidence,home,"map","threat-model:build",{"pipeline":"deterministic","offline":True,"variantScan":False},"partial")
    reference=mapped["modelRef"]
    save(evidence,"map-ref",reference)
    (evidence/"source-before.sha256").write_text(hashlib.sha256((root/"app.py").read_bytes()).hexdigest())
    map_functionality.execute(root,evidence,home,"question-map-review","campaign:context-map",{"threatModelRef":reference})
    save(evidence,"context-manifest-before",{"sha256":hashlib.sha256((root/".kuzushi/threat-models/manifest.json").read_bytes()).hexdigest()})
    (evidence/"runtime-home.txt").write_text(str(home))
    (evidence/"question-command.txt").write_text("ask Explain the two entry points in this accepted context.")
    (evidence/"question-edit.txt").write_text("\nKeep uncertainty explicit, including α.")


def question_plan(root):
    plans=[json.loads(p.read_text()) for p in (root/".kuzushi/v3/campaigns").glob("*/plan.json")]
    questions=[p for p in plans if p.get("tool")=="threat-model:ask"]
    assert len(questions)==1, questions
    return questions[0]


def check(root,evidence,stage,destination=None):
    destination=destination or evidence
    assert hashlib.sha256((root/"app.py").read_bytes()).hexdigest()==(evidence/"source-before.sha256").read_text()
    assert hashlib.sha256((root/".kuzushi/threat-models/manifest.json").read_bytes()).hexdigest()==json.loads((evidence/"context-manifest-before.json").read_text())["sha256"]
    plan=question_plan(root)
    assert plan["workers"]==1 and len(plan["jobs"])==1 and plan["jobs"][0]["tool"]=="threat-model:ask"
    assert plan["jobs"][0]["input"]["threatModelRef"]==json.loads((evidence/"map-ref.json").read_text())
    assert plan["jobs"][0]["input"]["question"]=="Explain the two entry points in this accepted context.\nKeep uncertainty explicit, including α."
    calls=evidence/"synthetic-provider-calls.jsonl"
    number=len(calls.read_text().splitlines()) if calls.exists() else 0
    if stage=="draft":
        assert number==0 and not (root/".kuzushi/v3/campaigns"/plan["campaignId"]/"queue.json").exists()
    else:
        wait_terminal(root,plan)
        number=len(calls.read_text().splitlines()) if calls.exists() else 0
        jobs=json.loads((root/".kuzushi/v3/campaigns"/plan["campaignId"]/"queue.json").read_text())["jobs"]
        assert len(jobs)==1
        job=jobs["context-001"]
        assert job["state"]=="completed" and job["attempts"]==job["dispatches"]==1,job
        result=json.loads((root/".kuzushi/v3/runs"/job["runId"]/"result.json").read_text())
        assert result["data"]["findingDecisionApplied"] is False
        assert result["data"]["answer"].startswith("Labeled synthetic answer")
        assert number==1
        with ledger(root,evidence) as db:
            assert db.execute("select count(*) from investigation_call_reservations").fetchone()[0]==1
            assert db.execute("select count(*) from finding_observations").fetchone()[0]==0
        (destination/"resume-command.txt").write_text("campaign "+plan["campaignId"])
    save(destination,stage+"-check",{"jobs":1,"workers":1,"syntheticProviderCalls":number,
        "liveProviderCalls":0,"sourceExecuted":False,"contextUnchanged":True,"findingDecisionsChanged":False})


def wait_terminal(root,plan):
    path=root/".kuzushi/v3/campaigns"/plan["campaignId"]/"queue.json"
    end=time.monotonic()+60
    while time.monotonic()<end:
        if path.exists() and all(j["state"] not in ["planned","running"] for j in json.loads(path.read_text())["jobs"].values()): return
        time.sleep(.2)
    raise RuntimeError("Observe the current question dispatcher; do not restart on an observation timeout")


if __name__=="__main__":
    root,evidence,stage=Path(sys.argv[1]).resolve(),Path(sys.argv[2]).resolve(),sys.argv[3]
    evidence.mkdir(parents=True,exist_ok=True)
    if stage=="seed": seed(root,evidence,Path(sys.argv[4]).resolve())
    elif stage=="recover": check(root,root.parent,"restarted",evidence)
    else: check(root,evidence,stage)
