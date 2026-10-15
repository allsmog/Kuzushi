"""Unprepared finite study choices in an owned native crash. No target execution."""
import hashlib
import json
import sys
from pathlib import Path

import context_checkpoint
import context_case_edit


def records(home, root):
    found = []
    for path in (home / ".kuzushi/v3/study-drafts").glob("*/*.json"):
        value = json.loads(path.read_text())
        if value["target"] == str(root.resolve()):
            found.append((path, value))
    resolved = {h for _, value in found for h in value["resolvedHashes"]}
    return [(p,v) for p,v in found if v["snapshot"] and hashlib.sha256(p.read_bytes()).hexdigest() not in resolved]


def verify_snapshot(root, evidence, home, stage):
    context_checkpoint.invariant(root, evidence)
    saved = records(home, root)
    if stage == "crash":
        assert len(saved) == 1, "One explicit unfinished study must remain before recovery"
    else:
        saved = [(p,v) for p,v in saved if v["snapshot"].get("nameEdit",{}).get("field",{}).get("text") == "Ower draft α"]
        assert len(saved) == 1, "The recovered edit must have one acknowledged checkpoint"
    path, value = saved[0]
    draft = value["snapshot"]
    assert len(draft["cases"]) == 2
    assert [case["passes"] for case in draft["cases"]] == [2,3]
    assert draft["baselineCaseId"] == draft["cases"][0]["id"]
    assert draft["cases"][0]["label"] == "Baseline policy"
    assert draft["scanInput"]["tasks"] == ["semgrep"]
    assert draft["scanInput"]["semgrepTimeoutMs"] == 60000
    for key in ["jobs","allowance","receipt","approved"]:
        assert key not in draft
    if stage == "crash":
        assert draft["nameEdit"]["field"] == {"text":"Owner draft α", "cursor":2}
        (evidence / "study-before.json").write_text(json.dumps(draft, indent=2) + "\n")
        context_checkpoint.crash_owned_shell(root, evidence, home, path, value)
    else:
        original = json.loads((evidence / "study-before.json").read_text())
        assert draft["cases"] == original["cases"]
        assert draft["investigationId"] == original["investigationId"]
        assert draft["nameEdit"]["field"] == {"text":"Ower draft α", "cursor":2}
        (evidence / "study-recovered.json").write_text(json.dumps({"exactReferencesRetained":True,"cursorRetained":True,"jobsStarted":0,"providerRequests":0,"sourceExecuted":False},indent=2)+"\n")


def prepared(root, evidence, home):
    context_checkpoint.invariant(root, evidence)
    plans = [json.loads(p.read_text()) for p in (root / ".kuzushi/v3/campaigns").glob("*/plan.json")]
    assert len(plans) == 1
    plan = plans[0]
    assert plan["kind"] == "context-matrix" and plan["jobCount"] == len(plan["jobs"]) == 5
    original = json.loads((evidence / "study-before.json").read_text())
    assert plan["investigationId"] == original["investigationId"]
    cases = plan["contextMatrix"]["cases"]
    assert [case["label"] for case in cases] == ["Baseline policy","Ower draft α"]
    assert [case["baseInput"]["threatModelRef"] for case in cases] == [case["threatModelRef"] for case in original["cases"]]
    assert not records(home,root), "Preparing the durable plan must resolve the adopted private draft"
    (evidence / "prepared-study.json").write_text(json.dumps({"campaignId":plan["campaignId"],"jobCount":5,"providerRequests":0,"queued":False,"approved":False},indent=2)+"\n")


if __name__ == "__main__":
    root, evidence, home = [Path(value) for value in sys.argv[1:4]]
    stage = sys.argv[4]
    if stage == "seed":
        context_case_edit.seed(root,evidence,home)
    elif stage == "prepared":
        prepared(root,evidence,home)
    else:
        verify_snapshot(root,evidence,home,stage)
