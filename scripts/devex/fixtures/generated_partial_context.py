"""Generate partial context through the native adapter, local scans and recovery."""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from investigation_journey import seed as seed_runtime
from installed_scope_study import native
from secret_settings import ledger
from partial_context_map import seek_limit


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def document():
    return {"version":"1", "methodology":"stride", "title":"Labeled generated partial source context",
        "systemContext":"Owned static source files support bounded source review. app.py contains a policy marker in a comment. oversized.txt exceeds complete content inspection. No target source executes and no runtime architecture or vulnerability is established.",
        "dfd":{"nodes":[
            {"id":"app","name":"Owned policy text","type":"data-store","trustZone":"repository",
             "description":"app.py contains a policy marker in a static comment.","purpose":"Supplies source text for an owner decision.","sourceRefs":["app.py:1"]},
            {"id":"oversized","name":"Partly inspected material","type":"data-store","trustZone":"repository",
             "description":"oversized.txt exceeds the bounded content inspection limit.","purpose":"Discloses material not fully represented in this context.","sourceRefs":["oversized.txt:1"]}],
            "flows":[],"trustBoundaries":[]},"threats":[],
        "openQuestions":["What meaning should the owner attach to the policy marker?","Unseen entry points remain unknown."],"summary":{}}


def source_hashes(root):
    return {n:hashlib.sha256((root/n).read_bytes()).hexdigest() for n in ["app.py","oversized.txt",".gitignore"]}


def partial_tool(root, evidence, name, tool):
    env = dict(os.environ, HOME=(evidence / "runtime-home.txt").read_text())
    result = subprocess.run([env["KUZUSHI_NATIVE_BIN"],"--plain","--target",str(root),"run",tool,"--input",'{"enrichment":false}' if tool=="context:build" else '{}'],env=env,capture_output=True,text=True,timeout=40)
    (evidence/(name+".stdout.json")).write_text(result.stdout)
    (evidence/(name+".stderr.log")).write_text(result.stderr)
    value=json.loads(result.stdout)
    assert result.returncode==4 and value["status"]=="partial" and value["ok"]


def seed(root, evidence, home):
    seed_runtime(root,evidence,home)
    for name in ["main.rs","config.env"]: (root/name).unlink(missing_ok=True)
    (root/"app.py").write_text("# OWNER_POLICY_REVIEW. Owned static source fixture, never executed.\n")
    (root/"oversized.txt").write_bytes(b'a'*262145)
    (root/".gitignore").write_text("# Owned fixture. Native workspace policy manages its artifacts.\n")
    subprocess.run(["git","-C",str(root),"add","."],check=True)
    (evidence/"runtime-home.txt").write_text(str(home))
    value=document();save(evidence,"response-document",value)
    value["title"]="Original inactive-test baseline"
    active=native(root,evidence,"original-context",["run","threat-model:import","--input",json.dumps({"document":value,"activate":True,"label":"Original"})])["data"]["modelRef"]
    shutil.copyfile(Path(__file__).with_name("partial_context_generation_provider.mjs"),evidence/"provider.mjs")
    partial_tool(root,evidence,"partial-snapshot","context:build")
    partial_tool(root,evidence,"partial-catalog","entry-points:extract")
    rules=evidence/"local-rules.yaml"
    rules.write_text('rules:\n  - id: owner-policy-review\n    languages: [generic]\n    pattern-regex: OWNER_POLICY_REVIEW\n    message: Owned policy marker needs an owner decision\n    severity: INFO\n')
    (evidence/"rule-setting.txt").write_text("set semgrepConfig "+json.dumps([str(rules)]))
    save(evidence,"before",{"active":active,"sources":source_hashes(root)})


def plans(root):
    return [json.loads(p.read_text()) for p in (root/".kuzushi/v3/campaigns").glob("*/plan.json")]


def context_plan(root):
    matches=[p for p in plans(root) if p["kind"]=="context-study"]
    assert len(matches)==1
    plan=matches[0];assert len(plan["jobs"])==plan["workers"]==1
    value=plan["jobs"][0]["input"]
    assert value["activate"] is False and value["newModel"] is True
    assert value["sources"]==["source-code"] and value["pipeline"]=="single"
    assert not value["variantScan"] and not value["emitFindings"]
    return plan


def calls(evidence):
    p=evidence/"partial-generation-calls.jsonl"
    return [json.loads(s) for s in p.read_text().splitlines()] if p.exists() else []


def generation(root,evidence,plan):
    queue=json.loads((root/".kuzushi/v3/campaigns"/plan["campaignId"]/"queue.json").read_text())["jobs"]
    assert len(queue)==1
    job=next(iter(queue.values()))
    assert job["state"]=="failed" and job["attempts"]==job["dispatches"]==1
    value=json.loads((root/".kuzushi/v3/runs"/job["runId"]/"result.json").read_text())
    assert value["status"]=="partial" and value["data"]["persisted"]
    ref=value["data"]["modelRef"];assert ref["revisionId"]
    doc=value["data"]["document"]
    assert doc["verification"]["verdict"]=="partial" and doc["verification"]["groundingSource"]=="partial-catalog"
    assert "262144" in doc["verification"]["groundingDegraded"]
    assert len(calls(evidence))==1 and calls(evidence)[0]["liveProviderRequests"]==0
    save(evidence,"generated-context",ref)
    return ref,job["runId"],doc


def map_state(root,run,selected):
    events=[json.loads(s) for s in (root/".kuzushi/v3/workflow/phase-attempts.jsonl").read_text().splitlines() if s]
    attempts=[e for e in events if e["event"]=="phase_attempt_completed" and e["phase"]=="map" and run in e["runRefs"]]
    assert len(attempts)==1 and attempts[0]["outcome"]=="partial"
    decisions=[e for e in events if e["event"]=="phase_attempt_disposition_recorded" and e["attemptId"]==attempts[0]["attemptId"]]
    assert len(decisions)==int(selected)
    if selected: assert decisions[0]["disposition"]["acknowledged_partial"] is True


def scan_state(root,evidence,plan,ref,stage):
    matches=[p for p in plans(root) if p["kind"]=="scan-batch"];assert len(matches)==1 and len(plans(root))==2
    scan=matches[0];assert scan["investigationId"]==plan["investigationId"]
    assert len(scan["jobs"])==3 and scan["workers"]==1
    assert scan["baseInput"]["threatModelRef"]==ref and scan["baseInput"]["paths"]==["app.py"]
    assert scan["baseInput"]["tasks"]==["semgrep"] and scan["equivalence"].get("model") is None
    for key in ["triage","verify","autoPatch","patch","pocExecution","dynamicAnalysis"]:assert not scan["baseInput"][key]
    if stage=="scan-draft":assert not (root/".kuzushi/v3/campaigns"/scan["campaignId"]/"queue.json").exists()
    else:
        jobs=json.loads((root/".kuzushi/v3/campaigns"/scan["campaignId"]/"queue.json").read_text())["jobs"]
        assert len(jobs)==3 and all(j["state"]=="completed" and j["attempts"]==j["dispatches"]==1 for j in jobs.values())
    return scan


def exported(root,plan,ref,doc):
    value=json.loads((root/".kuzushi/reports/findings.json").read_text())
    assert value["count"]==1 and value["findings"][0]["reviewDecision"]=="deferred"
    receipt=value["metadata"]["investigation"];assert receipt["campaignId"]==plan["campaignId"] and receipt["observationCount"]==3
    evidence=receipt["scope"]["contextEvidence"]
    assert evidence["contextRef"]==ref and evidence["verification"]==doc["verification"]
    current=receipt["allowance"]["currentInvestigation"]
    assert current["committedCalls"]==1 and current["unresolvedCalls"]==0
    assert current["limits"]=={"maxProviderCalls":1,"protectedReviewCalls":0}


def verify(root,evidence,stage):
    before=json.loads((evidence/"before.json").read_text());assert source_hashes(root)==before["sources"]
    manifest=json.loads((root/".kuzushi/threat-models/manifest.json").read_text());assert manifest["active"]==before["active"]
    plan=context_plan(root)
    if stage in ["draft","approved"]:
        assert len(plans(root))==1 and not calls(evidence)
        assert not (root/".kuzushi/v3/campaigns"/plan["campaignId"]/"queue.json").exists()
    else:
        ref,run,doc=generation(root,evidence,plan)
        if stage in ["mapped","accepted","scan-draft","scanned","exported","restarted"]:map_state(root,run,stage!="mapped")
        if stage in ["scan-draft","scanned","exported","restarted"]:
            scan=scan_state(root,evidence,plan,ref,stage)
            if stage in ["exported","restarted"]:exported(root,scan,ref,doc)
    with ledger(root,evidence) as db:
        tables={r[0] for r in db.execute("select name from sqlite_master where type='table'")}
        count=lambda name:db.execute("select count(*) from "+name).fetchone()[0] if name in tables else 0
        assert count("investigation_call_reservations")==int(stage not in ["draft","approved"])
        assert count("finding_observations")== (3 if stage in ["scanned","exported","restarted"] else 0)
    save(evidence,stage+"-check",{"sourceUnchanged":True,"activeUnchanged":True,"interceptedRequests":len(calls(evidence)),"liveProviderRequests":0,"sourceExecuted":False})


if __name__=="__main__":
    root,evidence=[Path(p).resolve() for p in sys.argv[1:3]];stage=sys.argv[3]
    if stage=="seed":seed(root,evidence,Path(sys.argv[4]).resolve())
    elif stage=="limit-page":seek_limit(root,evidence)
    elif stage=="result-limit-page":seek_limit(root,evidence,"result-limit-page")
    else:
        deadline=time.monotonic()+55
        while True:
            try:verify(root,evidence,stage);break
            except (AssertionError,FileNotFoundError,json.JSONDecodeError):
                if time.monotonic()>=deadline:raise
                time.sleep(0.2)
