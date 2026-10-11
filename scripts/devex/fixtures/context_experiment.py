"""Native fixed studies with intercepted transport and exact context receipts."""
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from rejected_context import execute
from context_diagram import document


def source_digest(root):
    return hashlib.sha256((root / "main.rs").read_bytes()).hexdigest()


def calls(evidence):
    path = evidence / "experiment-calls.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def accounting_visibility(root, evidence, visible):
    """Hide one owned fixture table, then restore all its rows unchanged."""
    with sqlite3.connect(root / ".kuzushi/v3/index.sqlite3") as db:
        if not visible:
            rows = db.execute("select * from investigation_allowance_revisions order by revision").fetchall()
            (evidence / "accounting-before-failure.json").write_text(json.dumps(rows))
            db.execute("alter table investigation_allowance_revisions rename to j108_hidden_allowance_revisions")
        else:
            db.execute("alter table j108_hidden_allowance_revisions rename to investigation_allowance_revisions")
            rows = db.execute("select * from investigation_allowance_revisions order by revision").fetchall()
            assert json.loads(json.dumps(rows)) == json.loads((evidence / "accounting-before-failure.json").read_text())
    assert len(calls(evidence)) == 3


def seed(root, evidence, home):
    repo = Path(__file__).resolve().parents[3]
    (root / "main.rs").write_text('// Owned greeting fixture, never executed.\nfn main() { println!("hello"); }\n')
    shutil.copyfile(repo / "scripts/devex/fixtures/experiment_provider.mjs", evidence / "provider.mjs")
    credentials = home / ".kuzushi/experiment-credentials.json"
    credentials.parent.mkdir(parents=True, exist_ok=True)
    credentials.write_text(json.dumps({"openai-codex":{"access":"offline-experiment-fixture","expires":99999999999999}}))
    credentials.chmod(0o600)
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    bridge = ["node", "--import", str(evidence / "provider.mjs"), str(repo / "scripts/langgraph-bridge.mjs")]
    config.write_text('model = "openai-codex:gpt-5.5"\n[runtime]\nthinking_level = "medium"\nlanggraph_bridge_command = ' + json.dumps(bridge)
                     + '\n[runtime.anthropic_oauth]\ncredentials_path = ' + json.dumps(str(credentials)) + '\nallow_env_token = false\n')
    refs = {}
    for name in ["Alpha", "Beta", "Gamma"]:
        value = document(name)
        value["systemContext"] = name + " labeled experiment context. The source prints a greeting."
        value["attackSurface"]["entryPoints"][0]["path"] = "main.rs"
        value["attackSurface"]["entryPoints"][0]["evidence"] = "main.rs:1"
        result = execute(root, home, evidence, "import-" + name, "threat-model:import", {"document":value,"label":name,"activate":True})
        refs[name] = result["modelRef"]
    plan = execute(root, home, evidence, "baseline-plan", "campaign:study", {
        "campaignId":"context-baseline","investigationId":"context-experiment-accounting","trials":3,
        "scanInput":{"taskMode":"manual","tasks":["agentic"],"threatModelRef":refs["Alpha"]}})
    execute(root, home, evidence, "baseline-approval", "campaign:approve-allowance", {
        "investigationId":"context-experiment-accounting","expectedRevision":0,"model":"openai-codex:gpt-5.5","maxProviderCalls":8,"protectedReviewCalls":2,
        "reason":"Six intercepted source-analysis requests across baseline and candidate; no live inference",
        "campaignId":plan["campaignId"],"campaignPlanSha256":plan["planSha256"],"campaignJobs":3,"maxJobAttempts":1})
    env = os.environ.copy(); env["HOME"] = str(home)
    result = subprocess.run([os.environ["KUZUSHI_NATIVE_BIN"],"--target",str(root),"campaign","batch","context-baseline"],env=env,capture_output=True,text=True,timeout=90)
    (evidence / "baseline-dispatch.log").write_text(result.stdout + result.stderr)
    queue = json.loads((root / ".kuzushi/v3/campaigns/context-baseline/queue.json").read_text())
    assert all(job["state"] == "completed" for job in queue["jobs"].values()), "Inspect baseline-dispatch.log"
    assert len(calls(evidence)) == 3
    before = {"refs":refs,"sourceSha256":source_digest(root),"activeMirrorSha256":hashlib.sha256((root / ".kuzushi/threat-model.json").read_bytes()).hexdigest()}
    (evidence / "before.json").write_text(json.dumps(before,indent=2) + "\n")
    (evidence / "open-command.txt").write_text("scan batch --prior-run context-baseline-trial-001-a1")


def verify(root, evidence, stage):
    before = json.loads((evidence / "before.json").read_text())
    assert source_digest(root) == before["sourceSha256"]
    manifest = json.loads((root / ".kuzushi/threat-models/manifest.json").read_text())
    assert manifest["active"] == before["refs"]["Gamma"]
    assert hashlib.sha256((root / ".kuzushi/threat-model.json").read_bytes()).hexdigest() == before["activeMirrorSha256"]
    plans = [json.loads(path.read_text()) for path in (root / ".kuzushi/v3/campaigns").glob("*/plan.json")]
    candidates = [plan for plan in plans if plan.get("contextExperiment")]
    if stage == "draft":
        assert len(candidates) == 1
    if stage == "finished":
        plan = candidates[0]
        queue = root / ".kuzushi/v3/campaigns" / plan["campaignId"] / "queue.json"
        for _ in range(45):
            if queue.exists() and all(job["state"] == "completed" for job in json.loads(queue.read_text())["jobs"].values()): break
            time.sleep(1)
        assert queue.exists() and all(job["state"] == "completed" for job in json.loads(queue.read_text())["jobs"].values())
    if candidates:
        plan = candidates[0]; condition = plan["contextExperiment"]
        assert condition["baselineRunId"] == "context-baseline-trial-001-a1"
        assert condition["investigationId"] == plan["investigationId"] == "context-experiment-accounting"
        assert condition["baseline"]["components"]["threatModel"] == before["refs"]["Alpha"]
        assert condition["candidate"]["components"]["threatModel"] == before["refs"]["Beta"]
        assert len(plan["jobs"]) == 3 and plan["workers"] == 1
        assert all(job["input"]["threatModelRef"] == before["refs"]["Beta"] for job in plan["jobs"])
        (evidence / "resume-command.txt").write_text("campaign " + plan["campaignId"])
    expected = 3 if stage == "draft" else 6
    assert len(calls(evidence)) == expected
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=ro",uri=True) as db:
        assert db.execute("select count(*) from investigation_call_reservations").fetchone()[0] == expected
        assert db.execute("select count(*) from investigation_allowance_revisions").fetchone()[0] == (1 if stage == "draft" else 2)
        assert db.execute("select count(*) from investigation_work_attempts").fetchone()[0] == expected
    (evidence / (stage + "-check.json")).write_text(json.dumps({"interceptedRequests":expected,"liveRequests":0,"sourceExecuted":False,
        "sourceAndActiveContextUnchanged":True,"baselineContext":before["refs"]["Alpha"],"candidateContext":before["refs"]["Beta"],"candidatePasses":3},indent=2) + "\n")


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "seed": seed(root,evidence,Path(sys.argv[4]).resolve())
    elif stage == "hide-accounting": accounting_visibility(root, evidence, False)
    elif stage == "restore-accounting": accounting_visibility(root, evidence, True)
    else: verify(root,evidence,stage)
