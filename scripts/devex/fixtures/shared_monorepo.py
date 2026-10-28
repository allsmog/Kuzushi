"""Reviewed shared context and bounded native batches over owned inert source."""
import hashlib
import json
import os
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

import bounded_semgrep
from installed_scope_study import native, current_counts, save
from semgrep_invocation_probe import install

NAMES = ["Service A", "Service B", "Root files"]
DEEP_PATH = "/".join(["deep"] * 40)
MARKERS = {"Service A":f"services/a/{DEEP_PATH}/f064.py", "Service B":f"services/b/{DEEP_PATH}/f064.py", "Root files":"loose.py"}


def hashes(root):
    result = {}
    for directory, _, files in os.walk(root, followlinks=False):
        if ".kuzushi" in Path(directory).relative_to(root).parts:
            continue
        for name in files:
            path = Path(directory) / name
            if path.suffix == ".py" and not path.is_symlink():
                result[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def seed(root, evidence, home):
    bounded_semgrep.seed(root, evidence, home)
    subprocess.run(["git", "init", "--quiet", "--initial-branch=main", str(home)], check=True)
    (root / "service/notice.py").unlink()
    (root / "service").rmdir()
    for service in ["a", "b"]:
        for index in range(65):
            parent = root / "services" / service / DEEP_PATH
            parent.mkdir(parents=True, exist_ok=True)
            marker = "OWNER_POLICY_REVIEW" if index == 64 else "ordinary notice"
            (parent / ("f%03d.py" % index)).write_text('# Owned inert text, never executed.\nprint("' + marker + '")\n')
    (root / "loose.py").write_text('# Owned inert shared root text, never executed.\nprint("OWNER_POLICY_REVIEW")\n')
    (root / "cycle").symlink_to(root, target_is_directory=True)
    doc = json.loads((root / ".kuzushi/manual-context.json").read_text())
    doc["title"] = "Owned monorepo source context"
    doc["systemContext"] = "131 owned Python text files are grouped under services/a, services/b and loose.py. Each service has 65 files including deep directories; only f064.py and loose.py contain the harmless owner-policy marker. No runtime application, vulnerability or execution is established. The cycle symlink is excluded from source reading."
    doc["dfd"]["nodes"] = [{"id":key,"name":label,"type":"data-store","trustZone":"repository",
        "description":path + " contains owned inert policy text.","purpose":"Provides literal source evidence for the bounded inspection."}
        for key,label,path in [("a","Service A source","services/a"),("b","Service B source","services/b"),("root","Root source","loose.py")]]
    doc["openQuestions"] = [{"id":"owner","question":"Which owner policy should classify these harmless markers?","targetElementIds":["a","b","root"]}]
    (root / ".kuzushi/manual-context.json").write_text(json.dumps(doc,indent=2) + "\n")
    (evidence / "runtime-home.txt").write_text(str(home))
    save(evidence,"source-before",hashes(root))
    probe = install(evidence)
    (evidence / "scanner-setting.txt").write_text("set semgrepBinary " + json.dumps(str(probe)))


def verify_native_membership(root, evidence):
    rows = [json.loads(line) for line in (evidence / "semgrep-invocations.jsonl").read_text().splitlines()]
    scans = [row for row in rows if "--" in row["argv"]]
    expected = set(json.loads((evidence / "source-before.json").read_text()))
    observed = Counter()
    batches = Counter()
    by_worker = {}
    for row in scans:
        assert Path(row["cwd"]).resolve() == root.resolve()
        arguments = row["argv"]
        assert "--json" in arguments and arguments[arguments.index("--metrics") + 1] == "off"
        files = arguments[arguments.index("--") + 1:]
        assert files and len(files) == len(set(files))
        assert set(files) <= expected
        labels = {"Service A" if name.startswith("services/a/") else
                  "Service B" if name.startswith("services/b/") else "Root files" for name in files}
        assert len(labels) == 1, "One native process crossed discovery boundaries"
        batches[next(iter(labels))] += 1
        observed.update(files)
        by_worker.setdefault(row["parentPid"], []).append(files)
    assert observed == Counter({name: 3 for name in expected})
    assert batches == {"Service A": 6, "Service B": 6, "Root files": 3}, batches
    assert len(by_worker) == 9, "Expected one executor process per fixed job"
    for groups in by_worker.values():
        members = [name for batch in groups for name in batch]
        assert len(members) == len(set(members))
        scope = next(iter(members)).split("/", 2)[:2]
        selected = {name for name in expected if name.split("/", 2)[:2] == scope}
        assert set(members) == selected
        assert len(groups) == (1 if selected == {"loose.py"} else 2)
    save(evidence,"native-membership",{"files":len(expected),"processes":len(scans),"processesByBoundary":dict(batches),
        "inspectionsPerFile":3,"sourceExecuted":False,"realEngine":json.loads((evidence / "semgrep-probe.json").read_text())})


def review(root, evidence):
    value = native(root,evidence,"scope-latest",["run","pack:scopes","--input",'{"operation":"latest"}'])
    return value["data"]["review"]


def verify_scope(root, evidence, stage):
    value = review(root,evidence)
    draft, coverage = value["record"]["draft"], value["coverage"]
    assert [scope["name"] for scope in draft["scopes"]] == NAMES
    assert coverage["enumeratedFiles"] == 131 and coverage["enumerationComplete"]
    assert coverage["uncoveredFiles"]["total"] == coverage["overlaps"]["total"] == 0
    assert [coverage["discoveryMembers"][scope["id"]]["total"] for scope in draft["scopes"]] == [65,65,1]
    if stage == "removed":
        assert draft["sharedScope"] is None and value["record"]["acceptance"] is None
    else:
        shared = draft["sharedScope"]
        assert shared["paths"] == ["loose.py"] and not draft["sharedDiscovery"]
        assert coverage["contextMembers"][shared["id"]]["files"] == ["loose.py"]
        assert shared["id"] not in coverage["discoveryMembers"]
        if stage == "accepted":
            assert value["record"]["acceptance"] is not None
            save(evidence,"accepted-scope",value)
        else:
            assert value["record"]["acceptance"] is None
            assert all(count in [None,0] for count in current_counts(root,evidence).values())
    save(evidence,"scope-"+stage,{"reference":value["reference"],"coverage":coverage,"sourceExecuted":False})


def selected_plan(root, evidence):
    plans = [json.loads(p.read_text()) for p in (root / ".kuzushi/v3/campaigns").glob("*/plan.json")]
    assert len(plans) == 1
    plan = plans[0]
    assert plan["kind"] == "scope-study", "No hidden or follow-up campaign is included"
    accepted = json.loads((evidence / "accepted-scope.json").read_text())
    assert plan["jobCount"] == len(plan["jobs"]) == 9 and plan["workers"] == 1
    cases = {case["id"]:case for case in plan["scopeStudy"]["cases"]}
    assert {case["label"] for case in cases.values()} == set(NAMES)
    for case in cases.values():
        scan = case["baseInput"]
        assert case["passes"] == 3 and case["equivalence"]["components"].get("model") is None
        assert scan["scanScopeRef"]["proposal"] == accepted["reference"]
        assert scan["tasks"] == ["semgrep"] and scan["semgrepTimeoutMs"] == 60000
        assert all(not scan[key] for key in ["triage","verify","patch","autoPatch","pocExecution","dynamicAnalysis"])
    assert plan["scopeStudy"]["unplannedScopeIds"] == []
    (evidence / "resume-command.txt").write_text("campaign " + plan["campaignId"])
    return plan, cases


def verify_work(root, evidence, stage):
    plan, cases = selected_plan(root,evidence)
    queue_path = root / ".kuzushi/v3/campaigns" / plan["campaignId"] / "queue.json"
    if stage == "draft":
        assert not queue_path.exists()
        assert all(count in [None,0] for count in current_counts(root,evidence).values())
        return
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if queue_path.exists() and all(job["state"] == "completed" for job in json.loads(queue_path.read_text())["jobs"].values()):
            break
        time.sleep(0.2)
    queue = json.loads(queue_path.read_text())["jobs"]
    assert len(queue) == 9 and all(job["state"] == "completed" and job["attempts"] == 1 for job in queue.values())
    for job in plan["jobs"]:
        result = json.loads((root / ".kuzushi/v3/runs" / queue[job["jobId"]]["runId"] / "result.json").read_text())
        assert result["status"] == "completed"
        findings = result["data"]["coreFindings"]
        assert len(findings) == 1 and findings[0]["file_path"].endswith(MARKERS[cases[job["caseId"]]["label"]])
    counts = current_counts(root,evidence)
    assert counts["finding_observations"] == counts["investigation_work_attempts"] == 9
    assert counts["investigation_call_reservations"] == 0
    verify_native_membership(root,evidence)
    occurrence = native(root,evidence,"scope-occurrence",["findings","batch",plan["campaignId"],"--json"])
    names = {case_id:case["label"] for case_id,case in cases.items()}
    suffixes = {"Service A":"a","Service B":"b","Root files":"root"}
    for case in occurrence["cases"]:
        work = case["occurrence"]
        assert work["planned"] == work["completed"] == 3 and len(work["rows"]) == 1
        assert work["rows"][0]["seen"] == 3
        assert MARKERS[names[case["id"]]] in work["rows"][0]["representativeLocation"]
        (evidence / ("open-" + suffixes[names[case["id"]]] + ".txt")).write_text("open " + work["rows"][0]["representativeFingerprint"])
    if stage in ["exported","restarted"]:
        assert counts["review_decisions"] == 3
        report = json.loads((root / ".kuzushi/reports/findings.json").read_text())
        assert report["count"] == 3
        assert all(finding["reviewDecision"] == "deferred" and finding["staticProofState"] == "signal_only" for finding in report["findings"])
        receipt = report["metadata"]["investigation"]
        assert receipt["campaignId"] == plan["campaignId"] and receipt["observationCount"] == 9
        assert receipt["reviewedCount"] == 3 and receipt["confirmedCount"] == 0
        assert receipt["unplannedScopeIds"] == []
        accepted = json.loads((evidence / "accepted-scope.json").read_text())
        for scope in receipt["scope"].values():
            assert scope["scanScopeRef"]["proposal"] == accepted["reference"]
            assert scope["acceptedScopeProposal"]["record"]["draft"]["sharedScope"]["paths"] == ["loose.py"]
            assert not scope["acceptedScopeProposal"]["record"]["draft"]["sharedDiscovery"]
        accounting = receipt["allowance"]["currentInvestigation"]
        assert accounting["committedCalls"] == accounting["unresolvedCalls"] == 0
        assert accounting["limits"] == {"maxProviderCalls":1,"protectedReviewCalls":1}
    save(evidence,stage+"-check",{"campaignId":plan["campaignId"],"cases":3,"jobs":9,"counts":counts,"providerCalls":0,"sourceExecuted":False})


def verify(root, evidence, stage):
    assert not (evidence / "denied-fetch.jsonl").exists(), "No provider transport is permitted"
    assert hashes(root) == json.loads((evidence / "source-before.json").read_text())
    manifest = root / ".kuzushi/threat-models/manifest.json"
    assert json.loads(manifest.read_text()).get("active") is None
    if stage in ["shared","accepted","removed"]:
        verify_scope(root,evidence,stage)
    else:
        verify_work(root,evidence,stage)
    if stage == "context-read":
        verify_context_reading(root,evidence)


def verify_context_reading(root, evidence):
    plan, _ = selected_plan(root,evidence)
    pages = sorted(evidence.glob("*-report-context-*.txt"))
    assert len(pages) == 7, "Read the full bounded detail-page sequence"
    text = "".join("".join(path.read_text().split()) for path in pages)
    for case in plan["scopeStudy"]["cases"]:
        label = "".join((case["label"] + " · Context reference:").split())
        assert label in text, "Missing visible context reference for " + case["label"]
        assert case["baseInput"]["threatModelRef"]["sha256"] in text
    summary = next(evidence.glob("*-report.txt")).read_text()
    assert "Frozen context revision for all 3 boundaries:" in summary
    assert summary.count("Context: frozen") == 1
    save(evidence,"report-context-reading",{"detailPages":len(pages),"boundaryReferences":3,
        "commonSummaryReferences":1,"sourceAndLedgerUnchanged":True,"providerCalls":0})


if __name__ == "__main__":
    root,evidence,stage = Path(sys.argv[1]),Path(sys.argv[2]),sys.argv[3]
    if stage == "seed":
        seed(root,evidence,Path(sys.argv[4]))
    else:
        verify(root,evidence,stage)
