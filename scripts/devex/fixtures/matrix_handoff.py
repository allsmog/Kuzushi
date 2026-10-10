"""Recover fresh, labeled synthetic receipts without executing source or models."""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from matrix_report import accounting


def phase_events(root):
    path = root / ".kuzushi/v3/workflow/phase-attempts.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()]


def matrix_plan(root):
    return next(json.loads(path.read_text())
                for path in (root / ".kuzushi/v3/campaigns").glob("*/plan.json")
                if json.loads(path.read_text()).get("kind") == "context-matrix")


def completed_queue(root, plan):
    path = root / ".kuzushi/v3/campaigns" / plan["campaignId"] / "queue.json"
    jobs = json.loads(path.read_text())["jobs"]
    assert len(jobs) == 9 and all(job["state"] == "completed" for job in jobs.values())
    return jobs


def recover(root, evidence, home, binary, plan, label):
    env = dict(os.environ, HOME=str(home))
    for key in ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "KUZUSHI_MODEL", "NODE_OPTIONS"]:
        env.pop(key, None)
    result = subprocess.run([str(binary), "--target", str(root), "campaign", "run",
                             plan["campaignId"], "--resume", "--workers", "1"],
                            env=env, text=True, capture_output=True, timeout=35)
    (evidence / (label + ".log")).write_text(result.stdout + result.stderr)
    assert result.returncode == 0, "Completed-work recovery failed; inspect " + label + ".log"


def seed(root, evidence, home, binary):
    output = evidence / "generated-target.txt"
    repo = Path(__file__).resolve().parents[3]
    env = dict(os.environ, KUZUSHI_DEVEX_MATRIX_TARGET_FILE=str(output))
    result = subprocess.run(["cargo", "test", "-p", "kuzushi-core", "--lib", "--locked",
        "workspace::application::investigation_report::tests::matrix::native_matrix_handoff_fixture",
        "--", "--ignored", "--exact"], cwd=repo, env=env, text=True, capture_output=True, timeout=180)
    (evidence / "generate-owned-receipts.log").write_text(result.stdout + result.stderr)
    assert result.returncode == 0, "Inspect generate-owned-receipts.log"
    root = Path(output.read_text()).resolve()
    assert "Owned report fixture, never executed" in (root / "main.rs").read_text()
    (evidence / "current-target").symlink_to(root, target_is_directory=True)
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('model = "openai-codex:gpt-5.5"\n')
    plan = matrix_plan(root)
    before = completed_queue(root, plan)
    receipt = {"source": hashlib.sha256((root / "main.rs").read_bytes()).hexdigest(),
               "mirror": hashlib.sha256((root / ".kuzushi/threat-model.json").read_bytes()).hexdigest(),
               "accounting": accounting(root), "jobs": before}
    (evidence / "fresh-before.json").write_text(json.dumps(receipt, indent=2) + "\n")
    path = root / ".kuzushi/v3/workflow/phase-attempts.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    assert not path.exists(), "Fresh fixture must not contain a previous phase decision"
    # This labeled fixture skips Map explicitly; it never claims an accepted Map.
    event = {"event": "phase_checkpoint_skipped", "phase": "map",
             "targetSnapshot": {"target": str(root), "dirty": False}, "recordedAtUnix": 1}
    path.write_text(json.dumps(event) + "\n")
    recover(root, evidence, home, binary, plan, "recover-completed")
    first = path.read_bytes()
    recover(root, evidence, home, binary, plan, "recover-again")
    assert path.read_bytes() == first, "Recovery must not duplicate phase results"
    assert completed_queue(root, plan) == before, "Completed jobs must remain untouched"
    verify(root, evidence, "unselected")


def verify(root, evidence, stage):
    root = Path((evidence / "generated-target.txt").read_text()).resolve()
    before = json.loads((evidence / "fresh-before.json").read_text())
    assert hashlib.sha256((root / "main.rs").read_bytes()).hexdigest() == before["source"]
    assert hashlib.sha256((root / ".kuzushi/threat-model.json").read_bytes()).hexdigest() == before["mirror"]
    assert json.loads(json.dumps(accounting(root))) == before["accounting"]
    assert completed_queue(root, matrix_plan(root)) == before["jobs"]
    events = phase_events(root)
    scans = [event for event in events if event.get("event") == "phase_attempt_completed"
             and event["phase"] == "scan"]
    assert len(scans) == 1 and scans[0]["outcome"] == "completed"
    assert len(scans[0]["runRefs"]) == 9
    decisions = [event for event in events
                 if event.get("event") == "phase_attempt_disposition_recorded"]
    if stage == "unselected":
        assert not decisions, "Recovery must wait for a human decision"
    else:
        assert len(decisions) == 1 and decisions[0]["disposition"]["kind"] == "selected"
        assert decisions[0]["attemptId"] == scans[0]["attemptId"]
    (evidence / (stage + "-handoff-check.json")).write_text(json.dumps({
        "scanAttempts": 1, "runReferences": 9, "decisions": len(decisions),
        "extraProviderRequests": 0, "extraJobs": 0, "sourceExecuted": False,
        "completedJobsUnchanged": True, "accountingUnchanged": True}, indent=2) + "\n")


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve(), Path(sys.argv[5]).resolve())
    else:
        verify(root, evidence, stage)
