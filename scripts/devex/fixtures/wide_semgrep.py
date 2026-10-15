"""Eight explicit scopes over 4,105 inert files, with real bounded scanner work."""
import hashlib
import json
import sys
import time
from pathlib import Path

import bounded_semgrep
import prepared_study_recovery
from installed_scope_study import current_counts, native, save
from semgrep_scale import install_single_worker_observer

IDS=list("abcdefgh")


def hashes(root):
    files={str(path.relative_to(root)):hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (root / "services").rglob("*.py")}
    files["loose.py"]=hashlib.sha256((root / "loose.py").read_bytes()).hexdigest()
    return files


def seed(root,evidence,home):
    bounded_semgrep.seed(root,evidence,home)
    (root / "service/notice.py").unlink()
    (root / "service").rmdir()
    for key in IDS:
        parent=root / "services" / key
        for index in range(512):
            directory=parent.joinpath(*(["deep"]*40)) if index==0 else parent
            directory.mkdir(parents=True,exist_ok=True)
            (directory / f"component-source-{index:04}.py").write_text('# Owned inert source. Never execute.\nprint("ordinary notice")\n')
        (parent / "z-owner-policy.py").write_text('# Owned inert source. Never execute.\nprint("OWNER_POLICY_REVIEW")\n')
    (root / "loose.py").write_text('# Owned inert root source. Never execute.\nprint("OWNER_POLICY_REVIEW")\n')
    (root / "cycle").symlink_to(root,target_is_directory=True)
    wrapper=install_single_worker_observer(evidence)
    (evidence / "binary-setting.txt").write_text("set semgrepBinary " + str(wrapper))
    (evidence / "runtime-home.txt").write_text(str(home))
    save(evidence,"source-before",hashes(root))
    doc=json.loads((root / ".kuzushi/manual-context.json").read_text())
    doc["title"]="Owned wide source policy context"
    doc["systemContext"]="4105 owned inert Python text files: eight services with 513 files each and loose.py. Each service has one owner-policy marker in z-owner-policy.py; loose.py has another. Each service has a forty-level source path. No runtime application, vulnerability or data flow is established. The cycle symlink is excluded."
    doc["dfd"]["nodes"]=[{"id":key,"name":"Service " + key.upper() + " text","type":"data-store","trustZone":"repository",
        "description":"services/" + key + " contains 513 owned text files.","purpose":"Supplies literal source for a bounded local-rule inspection."} for key in IDS]
    doc["dfd"]["nodes"].append({"id":"root","name":"Root policy text","type":"data-store","trustZone":"repository","description":"loose.py contains one owner-policy marker.","purpose":"Preserves parent-level discovery while supplying shared context."})
    doc["openQuestions"]=[{"id":"owner","question":"Which owner policy should classify these harmless markers?","targetElementIds":IDS+["root"]}]
    save(root / ".kuzushi","manual-context",doc)
    scopes=[]
    for key in IDS:
        scopes.append({"id":key,"name":"Service " + key.upper() + (" and root integration" if key=="h" else ""),
            "paths":["services/"+key]+(["loose.py"] if key=="h" else []),"rationale":"Operator-defined source boundary; root policy discovery is assigned only to H.","sharedDependencies":["shared-root"],"openQuestions":[]})
    shared={"id":"shared-root","name":"Shared root policy context","paths":["loose.py"],"rationale":"Context is inherited without additional discovery jobs.","sharedDependencies":[],"openQuestions":[]}
    native(root,evidence,"created-scopes",["run","pack:scopes","--input",json.dumps({"operation":"create","draft":{"schemaVersion":1,"scopes":scopes,"sharedScope":shared,"sharedDiscovery":False,"exclusions":[]}})])


def invariant(root,evidence):
    assert hashes(root)==json.loads((evidence / "source-before.json").read_text())
    assert json.loads((root / ".kuzushi/threat-models/manifest.json").read_text()).get("active") is None
    assert current_counts(root,evidence).get("investigation_call_reservations") in [None,0]


def plan(root,evidence):
    values=[json.loads(path.read_text()) for path in (root / ".kuzushi/v3/campaigns").glob("*/plan.json")]
    values=[value for value in values if value["kind"]=="scope-study"]
    assert len(values)==1
    value=values[0]
    assert len(value["jobs"])==value["jobCount"]==24 and value["workers"]==1
    cases=value["scopeStudy"]["cases"]
    assert {case["id"] for case in cases}==set(IDS)
    assert value["scopeStudy"]["unplannedScopeIds"]==[]
    for case in cases:
        assert case["passes"]==3
        assert case["baseInput"]["tasks"]==["semgrep"]
        assert case["baseInput"]["semgrepJobs"]==1 and case["baseInput"]["semgrepTimeoutMs"]==60000
        assert all(not case["baseInput"][key] for key in ["triage","verify","patch","pocExecution","dynamicAnalysis"])
    return value


def prepared(root,evidence):
    invariant(root,evidence)
    value=plan(root,evidence)
    assert not (root / ".kuzushi/v3/campaigns" / value["campaignId"] / "queue.json").exists()
    save(evidence,"wide-plan",value)
    (evidence / "resume-command.txt").write_text("campaign " + value["campaignId"])


def progress(root,evidence,minimum):
    value=plan(root,evidence)
    path=root / ".kuzushi/v3/campaigns" / value["campaignId"] / "queue.json"
    # Observation waits follow the accepted per-job maximum, not a speed claim.
    deadline=time.monotonic()+minimum*60+30
    while time.monotonic()<deadline:
        jobs=json.loads(path.read_text())["jobs"] if path.exists() else {}
        assert all(job["state"] in ["planned","running","completed"] for job in jobs.values()),jobs
        if sum(job["state"]=="completed" for job in jobs.values())>=minimum:
            save(evidence,f"progress-{minimum}",{"completed":sum(job["state"]=="completed" for job in jobs.values()),"fixedJobs":len(jobs)})
            return
        time.sleep(.2)
    raise AssertionError("Observe the same dispatcher; do not restart it after an observation timeout")


def completed(root,evidence,stage):
    invariant(root,evidence)
    value=plan(root,evidence)
    assert value==json.loads((evidence / "wide-plan.json").read_text())
    jobs=json.loads((root / ".kuzushi/v3/campaigns" / value["campaignId"] / "queue.json").read_text())["jobs"]
    assert len(jobs)==24 and all(job["state"]=="completed" and job["attempts"]==1 for job in jobs.values())
    for job in value["jobs"]:
        output=json.loads((root / ".kuzushi/v3/runs" / jobs[job["jobId"]]["runId"] / "result.json").read_text())
        findings=output["data"]["coreFindings"]
        expected={f"services/{job['caseId']}/z-owner-policy.py"}|({"loose.py"} if job["caseId"]=="h" else set())
        assert {row["file_path"] for row in findings}==expected
        receipt=output["data"]["nativeInspections"][0]
        assert receipt["configuredLimits"]["jobs"]==1 and receipt["exactFileBatching"]["maxEncodedArgumentBytes"]==12288
    counts=current_counts(root,evidence)
    assert counts["investigation_work_attempts"]==24 and counts["finding_observations"]==27
    batch=native(root,evidence,stage+"-occurrence",["findings","batch",value["campaignId"],"--json"])
    for case in batch["cases"]:
        occurrence=case["occurrence"]
        assert occurrence["completed"]==occurrence["planned"]==3
        assert all(row["seen"]==3 for row in occurrence["rows"])
        for index,row in enumerate(occurrence["rows"]):
            (evidence / f"open-{case['id']}-{index}.txt").write_text("open " + row["representativeFingerprint"])
    rows=[json.loads(line) for line in (evidence / "scanner-starts.jsonl").read_text().splitlines()]
    analyses=[row for row in rows if "--json" in row["argv"]]
    assert len(analyses)==48 and all(row["argv"][row["argv"].index("--jobs")+1]=="1" for row in analyses)
    if stage in ["exported","restarted"]:
        report=json.loads((root / ".kuzushi/reports/findings.json").read_text())
        assert report["count"]==counts["review_decisions"]==9
        assert all(row["reviewDecision"]=="deferred" for row in report["findings"])
        assert report["metadata"]["investigation"]["observationCount"]==27
    save(evidence,stage+"-check",{"jobs":24,"observations":27,"findings":9,"scannerProcesses":48,"sourceFilesUnchanged":4105,"counts":counts,"providerRequests":0,"sourceExecuted":False})


if __name__=="__main__":
    root,evidence,home=[Path(value).resolve() for value in sys.argv[1:4]]
    stage=sys.argv[4]
    if stage=="seed": seed(root,evidence,home)
    elif stage=="prepared": prepared(root,evidence)
    elif stage=="probe": prepared_study_recovery.probe_active_work(root,evidence,"wide-plan.json")
    elif stage.startswith("progress-"): progress(root,evidence,int(stage.split("-")[1]))
    else: completed(root,evidence,stage)
