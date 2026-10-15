"""One intercepted proposal over owned inert source. No scanner or source execution."""
import hashlib
import json
import shutil
import sys
import time
from pathlib import Path
from secret_settings import ledger


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def seed(root, evidence, home):
    (root / "proposal_source.py").write_text("# Owned inert source. Never executed.\n")
    save(evidence, "source-before", {"sha256": hashlib.sha256((root / "proposal_source.py").read_bytes()).hexdigest()})
    provider = evidence / "workflow-proposal-provider.mjs"
    shutil.copyfile(Path(__file__).with_name("workflow_proposal_provider.mjs"), provider)
    credentials = home / ".kuzushi/offline-oauth.json"
    credentials.parent.mkdir(parents=True, exist_ok=True)
    credentials.write_text('{"openai-codex":{"access":"offline-fixture","expires":99999999999999}}')
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    repo = Path(__file__).resolve().parents[3]
    config.write_text('model = "openai-codex:gpt-5.5"\n[runtime]\nthinking_level = "low"\nlanggraph_bridge_command = ' + json.dumps(["node", "--import", str(provider), str(repo / "scripts/langgraph-bridge.mjs")]) + '\n[runtime.anthropic_oauth]\ncredentials_path = ' + json.dumps(str(credentials)) + '\nallow_env_token = false\n')
    (evidence / "goal-edit.txt").write_text("\nKeep uncertainty explicit, including α.")


def proposal_plan(root):
    plans = [json.loads(path.read_text()) for path in (root / ".kuzushi/v3/campaigns").glob("*/plan.json")]
    matching = [plan for plan in plans if plan.get("tool") == "planner:propose"]
    assert len(matching) == 1, matching
    return matching[0]


def wait_terminal(root, plan):
    path = root / ".kuzushi/v3/campaigns" / plan["campaignId"] / "queue.json"
    deadline = time.monotonic() + 55
    while time.monotonic() < deadline:
        if path.exists():
            jobs = json.loads(path.read_text())["jobs"]
            if all(job["state"] not in ["planned", "running"] for job in jobs.values()):
                return jobs
        time.sleep(.2)
    raise RuntimeError("Inspect the existing proposal dispatcher after timeout; do not start another job")


def check(root, evidence, stage):
    plan = proposal_plan(root)
    assert plan["workers"] == 1 and len(plan["jobs"]) == 1
    job = plan["jobs"][0]
    assert job["tool"] == "planner:propose" and job["input"]["proposalConfigSha256"]
    assert job["input"]["goal"] == "Inspect this owned repository.\nKeep uncertainty explicit, including α."
    assert not job["input"].get("phase")
    calls = evidence / "proposal-calls.jsonl"
    number = len(calls.read_text().splitlines()) if calls.exists() else 0
    if stage == "draft":
        assert number == 0 and not (root / ".kuzushi/v3/campaigns" / plan["campaignId"] / "queue.json").exists()
    else:
        jobs = wait_terminal(root, plan)
        number = len(calls.read_text().splitlines()) if calls.exists() else 0
        assert len(jobs) == 1 and number == 1
        result_job = jobs["context-001"]
        assert result_job["state"] == "completed" and result_job["attempts"] == result_job["dispatches"] == 1, result_job
        result = json.loads((root / ".kuzushi/v3/runs" / result_job["runId"] / "result.json").read_text())
        assert result["data"]["proposal"]["changes"][0]["kind"] == "note"
        with ledger(root, evidence) as db:
            assert db.execute("select count(*) from investigation_call_reservations").fetchone()[0] == 1
            assert db.execute("select count(*) from finding_observations").fetchone()[0] == 0
        (evidence / "resume-command.txt").write_text("campaign " + plan["campaignId"])
    assert hashlib.sha256((root / "proposal_source.py").read_bytes()).hexdigest() == json.loads((evidence / "source-before.json").read_text())["sha256"]
    save(evidence, stage + "-check", {"fixedJobs": 1, "workers": 1, "interceptedRequests": number, "liveRequests": 0, "scanners": 0, "sourceExecuted": False, "sourceUnchanged": True})


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    else:
        check(root, evidence, stage)
