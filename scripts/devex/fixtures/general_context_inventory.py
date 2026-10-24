"""Bounded general context through source-only discovery, triage, export and restart."""
import hashlib
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from dfd_study import graph
from investigation_journey import seed as base_seed
from secret_settings import ledger
from installed_scope_study import native

CAMPAIGN = "bounded-filename-context"
INVESTIGATION = "bounded-filename-investigation"


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def source_hashes(root):
    names = json.loads((root.parent / "all-sources.json").read_text())
    return {name:hashlib.sha256((root / name).read_bytes()).hexdigest() for name in names}


def fixture_tool(root, evidence, name, tool, value):
    return native(root, evidence, name, ["run", tool, "--input", json.dumps(value)])


def seed(root, evidence, home):
    base_seed(root, evidence, home)
    (evidence / "runtime-home.txt").write_text(str(home))
    (root / "main.rs").write_text("// Owned inert source comments. Never compiled or executed.\n")
    (root / "app.py").write_text("# OWNER_POLICY_REVIEW. Owned inert source comment, never executed.\n")
    (root / "README.md").write_text("# Owned source inventory fixture\nStatic comments support a source-only context receipt demonstration. No deployed application or vulnerability is asserted.\n")
    (root / " literal 東京.rs").write_text("// Owned literal source path, never compiled or executed.\n")
    (root / "Cargo.lock").write_text('version = 4\n' + '# Owned static lockfile comment. Never built.\n' * 8_000)
    (root / "modules").mkdir()
    for index in range(55):
        (root / "modules" / ("part-%03d.rs" % index)).write_text("// Owned static source comments. Never compiled or executed.\n")
    (root / ".gitignore").write_text("ignored-note.txt\n")
    (root / "ignored-note.txt").write_text("PRIVATE_IGNORED_FIXTURE_MARKER. Owned static text.\n")
    subprocess.run(["git","-C",str(root),"add","."],check=True)
    names = subprocess.check_output(["git","-C",str(root),"ls-files","-z"],text=True).strip("\0").split("\0")
    names.sort(key=lambda name:(name.count("/"),name))
    assert len(names) == 62 and "ignored-note.txt" not in names
    save(evidence, "expected-inventory", names)
    save(evidence, "all-sources", names + ["ignored-note.txt"])
    shutil.copyfile(Path(__file__).with_name("general_context_inventory_provider.mjs"),evidence / "provider.mjs")
    active = fixture_tool(root, evidence, "original-context", "threat-model:import",
        {"document":graph("Original",["app.py"]),"label":"Original","activate":True})["data"]["modelRef"]
    plan = fixture_tool(root, evidence, "inventory-plan", "campaign:context-study", {
        "campaignId":CAMPAIGN,"investigationId":INVESTIGATION,
        "contextInput":{"maxElements":10,"maxThreats":4,"maxSourceBytes":65536,"contextLimit":200,"maxOutputTokens":2048}})["data"]
    fixture_tool(root, evidence, "inventory-approval", "campaign:approve-allowance", {
        "investigationId":INVESTIGATION,"expectedRevision":0,"model":plan["model"],"maxProviderCalls":1,"protectedReviewCalls":0,
        "reason":"Owned offline context and local scanner workflow; one intercepted request and no source execution",
        "campaignId":CAMPAIGN,"campaignPlanSha256":plan["planSha256"],"campaignJobs":1,"maxJobAttempts":1})
    (evidence / "context-command.txt").write_text("campaign " + CAMPAIGN)
    rules = evidence / "local-rules.yaml"
    rules.write_text('rules:\n  - id: owner-policy-review\n    languages: [generic]\n    pattern-regex: OWNER_POLICY_REVIEW\n    message: Owned policy marker needs an owner decision\n    severity: INFO\n')
    (evidence / "rule-setting.txt").write_text("set semgrepConfig " + str(rules))
    save(evidence,"before",{"active":active,"sources":source_hashes(root)})


def verify_context(root, evidence):
    before = json.loads((evidence / "before.json").read_text())
    assert source_hashes(root) == before["sources"]
    manifest = json.loads((root / ".kuzushi/threat-models/manifest.json").read_text())
    assert manifest["active"] == before["active"] and len(manifest["models"]) == 2
    folder = root / ".kuzushi/v3/campaigns" / CAMPAIGN
    queue = json.loads((folder / "queue.json").read_text())["jobs"]
    assert len(queue) == 1
    job = next(iter(queue.values()))
    if job["state"] in ["failed", "parked", "canceled"]:
        raise RuntimeError("Context job stopped: " + json.dumps(job))
    assert job["state"] == "completed" and job["attempts"] == job["dispatches"] == 1, job
    result = json.loads((root / ".kuzushi/v3/runs" / job["runId"] / "result.json").read_text())
    receipt = result["data"]["repositoryInventory"]
    assert receipt == result["data"]["document"]["provenance"]["repositoryInventory"]
    calls = [json.loads(line) for line in (evidence / "inventory-calls.jsonl").read_text().splitlines()]
    assert len(calls) == 1 and calls[0]["inventory"] == receipt
    assert receipt["listedFiles"] == 40 and receipt["enumeratedFiles"] == 62 and receipt["unlistedFiles"] == 22
    assert receipt["enumerationComplete"] and receipt["truncatedFileCount"] == 1 and not receipt["completeRepositoryCoverage"]
    save(evidence,"generated-context",result["data"]["modelRef"])
    with ledger(root,evidence) as db:
        assert db.execute("select count(*) from investigation_call_reservations").fetchone()[0] == 1
    return result["data"]["modelRef"]


def verify(root, evidence, stage):
    context = verify_context(root,evidence)
    plans = [json.loads(path.read_text()) for path in (root / ".kuzushi/v3/campaigns").glob("*/plan.json")]
    if stage in ["generated","read"]:
        assert len(plans) == 1
    else:
        scan = next(plan for plan in plans if plan["kind"] == "scan-batch")
        assert len(plans) == 2 and len(scan["jobs"]) == scan["trialsPlanned"] == 3 and scan["workers"] == 1
        assert scan["investigationId"] == INVESTIGATION
        assert scan["baseInput"]["threatModelRef"] == context and scan["baseInput"]["paths"] == ["app.py"]
        assert scan["baseInput"]["tasks"] == ["semgrep"]
        for key in ["triage","verify","patch","autoPatch","pocExecution","dynamicAnalysis"]: assert not scan["baseInput"][key]
        folder = root / ".kuzushi/v3/campaigns" / scan["campaignId"]
        if stage == "draft":
            assert not (folder / "queue.json").exists()
        else:
            queue = json.loads((folder / "queue.json").read_text())["jobs"]
            assert len(queue) == 3 and all(job["state"] == "completed" and job["attempts"] == job["dispatches"] == 1 for job in queue.values())
            outcome = native(root,evidence,"recurrence-"+stage,["findings","batch",scan["campaignId"],"--json"])
            assert len(outcome["rows"]) == 1 and outcome["rows"][0]["seen"] == 3
            (evidence / "open-finding.txt").write_text("open " + outcome["rows"][0]["representativeFingerprint"])
        if stage in ["exported","restarted"]:
            report = json.loads((root / ".kuzushi/reports/findings.json").read_text())
            assert report["count"] == 1 and report["findings"][0]["reviewDecision"] == "deferred"
            current = report["metadata"]["investigation"]["allowance"]["currentInvestigation"]
            assert current["investigationId"] == INVESTIGATION and current["committedCalls"] == 1
    save(evidence,stage+"-check",{"sourceUnchanged":True,"activeUnchanged":True,"interceptedRequests":1,"liveProviderRequests":0,"targetSourceExecuted":False,"modelRef":context})


def wait(root,evidence,stage):
    deadline = time.monotonic() + 65
    while True:
        try:
            verify(root,evidence,stage)
            return
        except (AssertionError, FileNotFoundError, json.JSONDecodeError):
            if time.monotonic() >= deadline: raise
            time.sleep(0.2)


if __name__ == "__main__":
    root,evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    if sys.argv[3] == "seed": seed(root,evidence,Path(sys.argv[4]).resolve())
    else: wait(root,evidence,sys.argv[3])
