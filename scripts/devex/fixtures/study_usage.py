"""Usage preview over a real executor and explicitly intercepted model transport."""
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True
from rejected_context import execute


def source_bytes(root):
    return {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in root.iterdir() if path.is_file()}


def seed(root, evidence, home):
    repo = Path(__file__).resolve().parents[3]
    root.joinpath("main.rs").write_text('fn main() { println!("Labeled usage fixture"); }\n')
    shutil.copyfile(repo / "scripts/devex/fixtures/usage_provider.mjs", evidence / "provider.mjs")
    credentials = home / ".kuzushi/usage-credentials.json"
    credentials.parent.mkdir(parents=True, exist_ok=True)
    credentials.write_text(json.dumps({"openai-codex": {"access": "offline-usage-fixture", "expires": 99999999999999}}))
    credentials.chmod(0o600)
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    bridge = ["node", "--import", str(evidence / "provider.mjs"), str(repo / "scripts/langgraph-bridge.mjs")]
    config.write_text('model = "openai-codex:gpt-5.5"\n[runtime]\nthinking_level = "medium"\nlanggraph_bridge_command = ' + json.dumps(bridge) + '\n[runtime.anthropic_oauth]\ncredentials_path = ' + json.dumps(str(credentials)) + '\nallow_env_token = false\n')
    scan_input = {"taskMode": "manual", "tasks": ["agentic"], "threatModelRef": None}
    plan = execute(root, home, evidence, "baseline-plan", "campaign:study", {
        "campaignId": "usage-baseline", "investigationId": "usage-accounting", "trials": 2, "scanInput": scan_input,
    })
    execute(root, home, evidence, "baseline-approval", "campaign:approve-allowance", {
        "investigationId": "usage-accounting", "expectedRevision": 0, "model": "openai-codex:gpt-5.5",
        "maxProviderCalls": 6, "protectedReviewCalls": 2, "reason": "Four intercepted requests; no live inference",
        "campaignId": plan["campaignId"], "campaignPlanSha256": plan["planSha256"], "campaignJobs": 2, "maxJobAttempts": 1,
    })
    environment = os.environ.copy()
    environment["HOME"] = str(home)
    binary = environment.get("KUZUSHI_NATIVE_BIN") or str(repo / "target/debug/kuzushi")
    result = subprocess.run([binary, "--target", str(root), "campaign", "batch", "usage-baseline"], env=environment, capture_output=True, text=True, timeout=90)
    (evidence / "baseline-dispatch.log").write_text(result.stdout + result.stderr)
    run = "usage-baseline-trial-001-a1"
    queue = json.loads(root.joinpath(".kuzushi/v3/campaigns/usage-baseline/queue.json").read_text())
    assert queue["jobs"]["trial-001"]["state"] == "completed", result.stderr
    assert len(evidence.joinpath("usage-provider-calls.jsonl").read_text().splitlines()) == 4
    execute(root, home, evidence, "future-plan", "campaign:study", {
        "campaignId": "usage-future", "investigationId": "usage-accounting", "trials": 3,
        "scanInput": scan_input, "baselineRunId": run,
    })
    (evidence / "future-command.txt").write_text("campaign usage-future")
    (evidence / "source-before.json").write_text(json.dumps(source_bytes(root)))
    verify(root, evidence)


def verify(root, evidence):
    assert source_bytes(root) == json.loads((evidence / "source-before.json").read_text())
    queue_path = root / ".kuzushi/v3/campaigns/usage-future/queue.json"
    if queue_path.exists():
        assert all(job.get("attempts", 0) == 0 for job in json.loads(queue_path.read_text()).get("jobs", {}).values())
    with sqlite3.connect(root.joinpath(".kuzushi/v3/index.sqlite3").as_uri() + "?mode=ro", uri=True) as connection:
        assert connection.execute("select count(*) from investigation_call_reservations").fetchone()[0] == 4
        assert connection.execute("select count(*) from investigation_allowance_revisions").fetchone()[0] == 1
    assert len((evidence / "usage-provider-calls.jsonl").read_text().splitlines()) == 4
    plan = json.loads(root.joinpath(".kuzushi/v3/campaigns/usage-future/plan.json").read_text())
    assert len(plan["jobs"]) == 3 and plan["workers"] == 1
    assert plan["resourceBaselineRunId"] == "usage-baseline-trial-001-a1"
    (evidence / "usage-check.json").write_text(json.dumps({"interceptedRequests": 4, "liveRequests": 0, "futureJobs": 3, "futureJobsStarted": 0, "allowanceRevisions": 1, "sourceUnchanged": True}, indent=2) + "\n")


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    else:
        verify(root, evidence)
