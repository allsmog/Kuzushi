"""Exact installed-scanner scopes and context provenance over owned inert text."""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import bounded_semgrep
from secret_settings import ledger

LOCAL_CONTEXT = "Service scope: service/notice.py contains a harmless owner-policy marker. The loose root file belongs to separate discovery work. No execution or vulnerability verdict is established."
MEMBERS = {"Service": "service/notice.py", "Root files": "loose.py"}


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def seed(root, evidence, home):
    bounded_semgrep.seed(root, evidence, home)
    (root / "loose.py").write_text('# Owned inert root policy text. Never executed.\nprint("OWNER_POLICY_REVIEW")\n')
    path = root / ".kuzushi/manual-context.json"
    doc = json.loads(path.read_text())
    doc["systemContext"] = "Two owned Python text files contain the same harmless owner-policy marker: service/notice.py and loose.py. Source is read only. No executed application, vulnerability or runtime flow is established."
    doc["dfd"]["nodes"][1]["description"] = "loose.py contains the OWNER_POLICY_REVIEW literal at the repository root."
    path.write_text(json.dumps(doc, indent=2) + "\n")
    save(evidence, "source-before", bounded_semgrep.source_hashes(root))
    (evidence / "runtime-home.txt").write_text(str(home))
    (evidence / "local-context.txt").write_text(LOCAL_CONTEXT)


def native(root, evidence, name, arguments):
    env = dict(os.environ, HOME=(evidence / "runtime-home.txt").read_text())
    result = subprocess.run([env["KUZUSHI_NATIVE_BIN"], "--plain", "--target", str(root), *arguments],
                            env=env, capture_output=True, text=True, timeout=30)
    (evidence / (name + ".stdout.json")).write_text(result.stdout)
    (evidence / (name + ".stderr.txt")).write_text(result.stderr)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def current_counts(root, evidence):
    with ledger(root, evidence) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        return {name: db.execute("select count(*) from " + name).fetchone()[0] if name in tables else None
                for name in ["finding_observations", "investigation_call_reservations", "investigation_work_attempts", "review_decisions"]}


def verify_source(root, evidence):
    assert bounded_semgrep.source_hashes(root) == json.loads((evidence / "source-before.json").read_text())
    manifest = root / ".kuzushi/threat-models/manifest.json"
    if manifest.exists():
        assert json.loads(manifest.read_text()).get("active") is None


def verify_boundaries(root, evidence, stage):
    result = native(root, evidence, "scopes-" + stage, ["run", "pack:scopes", "--input", '{"operation":"latest"}'])
    review = result["data"]["review"]
    assert review is not None
    record, coverage = review["record"], review["coverage"]
    scopes = record["draft"]["scopes"]
    assert {scope["name"]: scope["paths"] for scope in scopes} == {"Service":["service"],"Root files":["loose.py"]}
    assert coverage["enumerationComplete"] and coverage["enumeratedFiles"] == 2
    assert coverage["uncoveredFiles"]["total"] == coverage["overlaps"]["total"] == 0
    assert {scope["name"]: coverage["discoveryMembers"][scope["id"]]["files"] for scope in scopes} == {key:[member] for key,member in MEMBERS.items()}
    assert not record["draft"]["sharedDiscovery"] and not record["draft"]["sharedScope"]
    if stage == "split":
        assert record["acceptance"] is None
    else:
        assert record["acceptance"] is not None
        save(evidence, "accepted-scopes", review)
    assert not list((root / ".kuzushi/v3/campaigns").glob("*/plan.json"))
    assert all(value in [None,0] for value in current_counts(root,evidence).values())
    save(evidence, "boundaries-" + stage, {"reference":review["reference"],"coverage":coverage,"noJobs":True})


def context_references(root):
    imports = bounded_semgrep.run_results(root, "threat-model:import")
    assert len(imports) == 1
    common = imports[0][1]["data"]["modelRef"]
    manifest = json.loads((root / ".kuzushi/threat-models/manifest.json").read_text())
    assert len(manifest["models"]) == 2 and manifest.get("active") is None
    copy = next(model for model in manifest["models"] if model["modelId"] != common["modelId"])
    revision = copy["revisions"][-1]
    local = {"modelId":copy["modelId"],"revisionId":revision["revisionId"],"sha256":revision["sha256"]}
    document = root / ".kuzushi/threat-models/objects" / ("sha256-" + local["sha256"].removeprefix("sha256:") + ".json")
    assert json.loads(document.read_text())["systemContext"] == LOCAL_CONTEXT
    return common, local


def selected_plan(root, evidence):
    plans = [json.loads(p.read_text()) for p in (root / ".kuzushi/v3/campaigns").glob("*/plan.json")]
    plans = [value for value in plans if value["kind"] == "scope-study"]
    assert len(plans) == 1
    value = plans[0]
    assert value["jobCount"] == len(value["jobs"]) == 6 and value["workers"] == 1
    common, local = context_references(root)
    metadata = value["scopeStudy"]
    assert metadata["inheritedThreatModelRef"] == common and metadata["unplannedScopeIds"] == []
    cases = {case["id"]:case for case in metadata["cases"]}
    assert {case["label"] for case in cases.values()} == set(MEMBERS)
    reference = json.loads((evidence / "accepted-scopes.json").read_text())["reference"]
    for scope_id, case in cases.items():
        scan = case["baseInput"]
        assert case["passes"] == 3 and case["equivalence"]["components"].get("model") is None
        assert scan["tasks"] == ["semgrep"] and scan["semgrepTimeoutMs"] == 60000
        assert scan["semgrepConfig"] == [str(evidence / "local-rules.yaml")]
        assert scan["scanScopeRef"] == {"proposal":reference,"scopeId":scope_id}
        assert scan["threatModelRef"] == (local if case["label"] == "Service" else common)
        assert all(not scan[key] for key in ["triage","verify","autoPatch","patch","pocExecution","dynamicAnalysis"])
    for job in value["jobs"]:
        assert job["input"]["threatModelRef"] == cases[job["caseId"]]["baseInput"]["threatModelRef"]
    (evidence / "resume-command.txt").write_text("campaign " + value["campaignId"])
    return value


def verify_completed(root, evidence, value):
    queue = json.loads((root / ".kuzushi/v3/campaigns" / value["campaignId"] / "queue.json").read_text())
    assert len(queue["jobs"]) == 6
    assert all(job["state"] == "completed" and job["attempts"] == 1 for job in queue["jobs"].values())
    names = {case["id"]:case["label"] for case in value["scopeStudy"]["cases"]}
    for job in value["jobs"]:
        run_id = queue["jobs"][job["jobId"]]["runId"]
        result = json.loads((root / ".kuzushi/v3/runs" / run_id / "result.json").read_text())
        assert result["status"] == "completed", result["summary"]
        findings = result["data"]["coreFindings"]
        assert len(findings) == 1 and findings[0]["file_path"] == MEMBERS[names[job["caseId"]]]
    counts = current_counts(root,evidence)
    assert counts["finding_observations"] == counts["investigation_work_attempts"] == 6
    assert counts["investigation_call_reservations"] == 0
    occurrence = native(root,evidence,"scope-occurrence",["findings","batch",value["campaignId"],"--json"])
    for case in occurrence["cases"]:
        work = case["occurrence"]
        assert work["planned"] == work["completed"] == 3 and len(work["rows"]) == 1
        assert work["rows"][0]["seen"] == 3
        assert MEMBERS[names[case["id"]]] in work["rows"][0]["representativeLocation"]
        suffix = "service" if names[case["id"]] == "Service" else "root"
        (evidence / ("open-" + suffix + ".txt")).write_text("open " + work["rows"][0]["representativeFingerprint"])
    return counts


def verify_export(root, evidence, value):
    report = json.loads((root / ".kuzushi/reports/findings.json").read_text())
    assert report["count"] == 2
    assert all(finding["reviewDecision"] == "deferred" and finding["staticProofState"] == "signal_only" for finding in report["findings"])
    receipt = report["metadata"]["investigation"]
    assert receipt["campaignId"] == value["campaignId"] and receipt["observationCount"] == 6
    assert receipt["confirmedCount"] == 0 and receipt["reviewedCount"] == 2
    assert {case["id"]:case["equivalence"] for case in receipt["cases"]} == {case["id"]:case["equivalence"] for case in value["scopeStudy"]["cases"]}
    assert set(receipt["scope"]) == {case["id"] for case in value["scopeStudy"]["cases"]} and receipt["unplannedScopeIds"] == []
    accounting = receipt["allowance"]["currentInvestigation"]
    assert accounting["committedCalls"] == accounting["unresolvedCalls"] == 0
    assert accounting["limits"] == {"maxProviderCalls":1,"protectedReviewCalls":1}


def verify(root, evidence, stage):
    verify_source(root,evidence)
    if stage in ["split","accepted"]:
        return verify_boundaries(root,evidence,stage)
    value = selected_plan(root,evidence)
    if stage == "draft":
        assert not (root / ".kuzushi/v3/campaigns" / value["campaignId"] / "queue.json").exists()
        counts = current_counts(root,evidence)
        assert all(count in [None,0] for count in counts.values())
    else:
        deadline = time.monotonic() + 45
        while True:
            try:
                counts = verify_completed(root,evidence,value)
                break
            except (AssertionError,FileNotFoundError):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.2)
    if stage in ["exported","restarted"]:
        assert counts["review_decisions"] == 2
        verify_export(root,evidence,value)
    save(evidence,stage + "-check",{"campaignId":value["campaignId"],"counts":counts,"source":bounded_semgrep.source_hashes(root),
        "fixedJobs":6,"passesPerScope":3,"sourceExecuted":False,"globalContextUnchanged":True})


if __name__ == "__main__":
    root,evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    stage = sys.argv[3]
    if stage == "seed":
        seed(root,evidence,Path(sys.argv[4]).resolve())
    else:
        verify(root,evidence,stage)
