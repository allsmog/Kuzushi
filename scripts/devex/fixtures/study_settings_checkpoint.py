"""Ordinary study and goal recovery on owned inert source. No target execution."""
import hashlib
import json
import sys
from pathlib import Path

import bounded_semgrep
import context_checkpoint
import investigation_brief

TEXT = "Goal α\nInspect owner policy and preserve protected review. 東京 context remains source-only."
EDITED = "Gol α\nInspect owner policy and preserve protected review. 東京 context remains source-only."


def records(home, root):
    items = []
    for path in (home / ".kuzushi/v3/study-drafts").glob("*/*.json"):
        value = json.loads(path.read_text())
        if value["target"] == str(root.resolve()):
            items.append((path,value))
    resolved = {h for _,v in items for h in v["resolvedHashes"]}
    return [(p,v) for p,v in items if v["snapshot"] and hashlib.sha256(p.read_bytes()).hexdigest() not in resolved]


def invariant(root,evidence):
    context_checkpoint.invariant(root,evidence)


def save_goal(root,evidence,name,text,revision):
    return investigation_brief.native(root,evidence,name,"campaign:brief",{"mode":"save","text":text,"expectedRevision":revision})["data"]["brief"]


def crash(root,evidence,home):
    invariant(root,evidence)
    saved=records(home,root)
    assert len(saved)==1
    path,value=saved[0]
    draft=value["snapshot"]
    assert draft["trials"]==2 and draft["requestedWorkers"]==1 and draft["cases"]==[]
    assert draft["maxProviderCalls"]==5 and draft["protectedReviewCalls"]==2
    assert draft["scanInput"]["tasks"]==["semgrep"]
    assert draft["briefDraft"]["baseRef"]["revision"]==1
    assert draft["briefDraft"]["field"]=={"text":TEXT,"cursor":2}
    (evidence/"settings-before.json").write_text(json.dumps(draft,indent=2)+"\n")
    context_checkpoint.crash_owned_shell(root,evidence,home,path,value)
    newer=save_goal(root,evidence,"newer-accepted-goal","Another accepted operator goal",1)
    assert newer["reference"]["revision"]==2


def recovered(root,evidence,home):
    invariant(root,evidence)
    found=[v["snapshot"] for _,v in records(home,root) if v["snapshot"].get("briefDraft",{}).get("field",{}).get("text")==EDITED]
    assert len(found)==1
    draft=found[0]
    original=json.loads((evidence/"settings-before.json").read_text())
    assert draft["investigationId"]==original["investigationId"]
    for key in ["trials","requestedWorkers","scanInput","maxProviderCalls","protectedReviewCalls"]:
        assert draft[key]==original[key]
    assert draft["briefDraft"]["baseRef"]==original["briefDraft"]["baseRef"]
    assert draft["briefDraft"]["field"]["cursor"]==2
    current=investigation_brief.current(root,evidence,"current-after-recovery")
    assert current["reference"]["revision"]==2
    assert current["document"]["text"]=="Another accepted operator goal"


def prepared(root,evidence,home):
    invariant(root,evidence)
    plans=[json.loads(p.read_text()) for p in (root/".kuzushi/v3/campaigns").glob("*/plan.json")]
    assert len(plans)==1
    plan=plans[0]
    original=json.loads((evidence/"settings-before.json").read_text())
    assert plan["investigationId"]==original["investigationId"]
    assert plan["kind"]=="scan-batch" and plan["trialsPlanned"]==len(plan["jobs"])==2
    assert plan["workers"]==1 and plan["baseInput"]["tasks"]==["semgrep"]
    assert plan["investigationBrief"]["reference"]["revision"]==3
    assert plan["investigationBrief"]["document"]["text"]==EDITED
    assert not records(home,root)
    (evidence/"prepared-settings-check.json").write_text(json.dumps({"jobCount":2,"providerRequests":0,"queueCreated":False,"sourceExecuted":False,"goalRevision":3,"spendingApproved":False},indent=2)+"\n")


if __name__=="__main__":
    root,evidence,home=[Path(v) for v in sys.argv[1:4]]
    stage=sys.argv[4]
    if stage=="seed":
        bounded_semgrep.seed(root,evidence,home)
        (evidence/"settings-goal.txt").write_text(TEXT)
    elif stage=="base":
        save_goal(root,evidence,"baseline-goal","Baseline accepted operator intent",0)
    elif stage=="crash":
        crash(root,evidence,home)
    elif stage=="recovered":
        recovered(root,evidence,home)
    else:
        prepared(root,evidence,home)
