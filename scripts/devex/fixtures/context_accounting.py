"""Actual context copies and accounting, with one fully intercepted source-only request."""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path
import context_regeneration as base
from context_edit import object_path


INVESTIGATION = "copy-accounting"
CAMPAIGN = "copy-accounting-generation"
RUN = "copy-generation-run"


def run(binary, root, evidence, home, label, tool, value, run_id=None):
    environment = os.environ.copy()
    for name in ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "KUZUSHI_MODEL", "KUZUSHI_LANGGRAPH_BRIDGE", "NODE_OPTIONS"]:
        environment.pop(name, None)
    environment["HOME"] = str(home)
    command = [binary, "--target", str(root), "run", tool, "--input", "-"]
    if run_id:
        command += ["--run-id", run_id]
    result = subprocess.run(command, input=json.dumps(value), text=True, capture_output=True,
        timeout=55, check=False, env=environment)
    (evidence / (label + ".stdout.json")).write_text(result.stdout)
    (evidence / (label + ".stderr.txt")).write_text(result.stderr)
    assert result.returncode == 0, (label, result.stderr)
    output = json.loads(result.stdout)
    assert output.get("status") != "failed" and output.get("ok") is not False, label
    return output


def sources(root):
    return {path.name:hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.iterdir() if path.is_file()}


def seed(root, evidence, home):
    base.seed(root, evidence, home)
    binary = os.environ["KUZUSHI_NATIVE_BIN"]
    before = json.loads((evidence / "before.json").read_text())
    draft = run(binary, root, evidence, home, "generation-draft", "campaign:context-study", {
        "campaignId":CAMPAIGN,"investigationId":INVESTIGATION,"generationTool":"threat-model:regenerate",
        "contextInput":{"threatModelRef":before["references"]["selected"],
            "fields":["/dfd/nodes/1/purpose"],"guidance":(evidence / "guidance.txt").read_text()}})
    run(binary, root, evidence, home, "generation-approval", "campaign:approve-allowance", {
        "investigationId":INVESTIGATION,"expectedRevision":0,"model":"openai-codex:gpt-5.5",
        "maxProviderCalls":5,"protectedReviewCalls":2,"reason":"One owned offline intercepted context request",
        "campaignId":CAMPAIGN,"campaignPlanSha256":draft["data"]["planSha256"],"campaignJobs":1,"maxJobAttempts":1})
    plan = json.loads((root / ".kuzushi/v3/campaigns" / CAMPAIGN / "plan.json").read_text())
    value = plan["jobs"][0]["input"]
    value["allowanceRef"] = {"schemaVersion":1,"investigationId":INVESTIGATION,"revision":1,"workId":CAMPAIGN + ":context-001"}
    generated = run(binary, root, evidence, home, "regeneration", "threat-model:regenerate", value, RUN)
    queue = root / ".kuzushi/v3/campaigns" / CAMPAIGN / "queue.json"
    queue.write_text(json.dumps({"jobs":{"context-001":{"state":"completed","runId":RUN,"attempts":1}}}) + "\n")
    assert generated["data"]["activated"] is False
    (evidence / "generated-ref.json").write_text(json.dumps(generated["data"]["modelRef"]) + "\n")
    (evidence / "sources-before.json").write_text(json.dumps(sources(root),indent=2) + "\n")
    inspect(root, evidence, "seeded")


def inspect(root, evidence, stage):
    before, manifest = base.unchanged(root, evidence)
    assert sources(root) == json.loads((evidence / "sources-before.json").read_text())
    assert len((evidence / "provider-calls.jsonl").read_text().splitlines()) == 1
    original = json.loads((evidence / "generated-ref.json").read_text())
    assert len(manifest["models"]) == 3
    revisions = manifest["models"][2]["revisions"]
    assert len(revisions) == (1 if stage == "seeded" else 2)
    if stage != "seeded":
        latest = revisions[-1]
        checked = {"modelId":original["modelId"],"revisionId":latest["revisionId"],"sha256":latest["sha256"]}
        assert latest["sourceRevisionId"] == original["revisionId"] and latest["source"] == "verify"
        value = json.loads(object_path(root, checked).read_text())
        assert "verification" in value
        assert value["provenance"]["regeneration"]["sourceModelRef"] == before["references"]["selected"]
        (evidence / "checked-ref.json").write_text(json.dumps(checked) + "\n")
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
        rows = db.execute("select revision, approval_json from investigation_allowance_revisions where investigation_id=? order by revision", (INVESTIGATION,)).fetchall()
        expected = 2 if stage in ["approved","recovered","damaged","repaired"] else 1
        assert len(rows) == expected
        approval = json.loads(rows[-1][1])
        assert approval["limits"] == {"maxProviderCalls":5,"protectedReviewCalls":2}
        assert db.execute("select count(*) from investigation_call_reservations").fetchone()[0] == 1
        assert db.execute("select count(*) from investigation_work_attempts").fetchone()[0] == 1
        assert db.execute("select count(*) from finding_observations").fetchone()[0] == 0
    if stage in ["pending","accepted","draft","approved","recovered","damaged","repaired"]:
        events = [json.loads(line) for line in (root / ".kuzushi/v3/workflow/phase-attempts.jsonl").read_text().splitlines() if line]
        decisions = [event for event in events if event["event"] == "phase_attempt_disposition_recorded"]
        assert len(decisions) == (0 if stage == "pending" else 1)
    if stage in ["draft","approved","recovered","damaged","repaired"]:
        scans = [plan for plan in base.plans(root) if plan.get("kind") == "scan-batch"]
        assert len(scans) == 1 and scans[0]["investigationId"] == INVESTIGATION
        scan = scans[0]
        assert len(scan["jobs"]) == 3 and scan["workers"] == 1
        assert scan["baseInput"]["threatModelRef"] == checked
        assert not (root / ".kuzushi/v3/campaigns" / scan["campaignId"] / "queue.json").exists()
        if expected == 2:
            assert approval["workPlan"]["campaignId"] == scan["campaignId"]
        (evidence / "resume-command.txt").write_text("campaign " + scan["campaignId"])
    (evidence / (stage + "-check.json")).write_text(json.dumps({"stage":stage,"investigationId":INVESTIGATION,
        "recordedRequests":1,"protectedReviewCalls":2,"totalCalls":5,"liveProviderRequests":0,
        "sourceExecuted":False,"discoveryJobsStarted":0,"activeContextUnchanged":True},indent=2) + "\n")


root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
if stage == "seed":
    seed(root, evidence, Path(sys.argv[4]).resolve())
elif stage == "damage":
    path = root / ".kuzushi/v3/runs" / RUN / "result.json"
    (evidence / "origin-result.bin").write_bytes(path.read_bytes())
    path.write_text("{}\n")
elif stage == "repair":
    (root / ".kuzushi/v3/runs" / RUN / "result.json").write_bytes((evidence / "origin-result.bin").read_bytes())
else:
    inspect(root, evidence, stage)
