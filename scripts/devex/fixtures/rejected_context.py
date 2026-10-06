"""Real context executor with intercepted invalid output. No live inference."""
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path


def execute(root, home, evidence, name, tool, value):
    path = evidence / (name + "-input.json")
    path.write_text(json.dumps(value, indent=2) + "\n")
    environment = os.environ.copy()
    environment["HOME"] = str(home)
    binary = environment.get("KUZUSHI_NATIVE_BIN") or str(Path(__file__).resolve().parents[3] / "target/debug/kuzushi")
    result = subprocess.run([binary, "--plain", "--target", str(root), "run", tool, "--input", "@" + str(path)], env=environment, capture_output=True, text=True)
    (evidence / (name + "-result.json")).write_text(result.stdout)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)["data"]


def seed(root, evidence, home):
    root.joinpath("main.rs").write_text('fn main() { println!("Labeled source fixture"); }\n')
    repo = Path(__file__).resolve().parents[3]
    shutil.copyfile(repo / "scripts/devex/fixtures/rejected_provider.mjs", evidence / "provider.mjs")
    credentials = home / ".kuzushi/rejected-credentials.json"
    credentials.parent.mkdir(parents=True, exist_ok=True)
    credentials.write_text(json.dumps({"openai-codex": {"access": "offline-rejected-fixture", "expires": 99999999999999}}))
    credentials.chmod(0o600)
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    command = ["node", "--import", str(evidence / "provider.mjs"), str(repo / "scripts/langgraph-bridge.mjs")]
    config.write_text('model = "openai-codex:gpt-5.5"\n[runtime]\nthinking_level = "medium"\nlanggraph_bridge_command = ' + json.dumps(command) + '\n[runtime.anthropic_oauth]\ncredentials_path = ' + json.dumps(str(credentials)) + '\nallow_env_token = false\n')
    data = execute(root, home, evidence, "context-plan", "campaign:context-study", {
        "campaignId": "rejected-context", "investigationId": "rejected-context-accounting",
        "contextInput": {"saveRejectedOutput": True, "maxSourceBytes": 12000, "maxElements": 10, "maxThreats": 6, "maxOutputTokens": 1024},
    })
    execute(root, home, evidence, "context-approval", "campaign:approve-allowance", {
        "investigationId": "rejected-context-accounting", "expectedRevision": 0,
        "model": "openai-codex:gpt-5.5", "maxProviderCalls": 8, "protectedReviewCalls": 2,
        "reason": "Offline intercepted JSON rejection; one fixed context job",
        "campaignId": data["campaignId"], "campaignPlanSha256": data["planSha256"],
        "campaignJobs": 1, "maxJobAttempts": 1,
    })
    (evidence / "context-command.txt").write_text("campaign rejected-context")
    (evidence / "source-before.json").write_text(json.dumps(source_bytes(root)))


def source_bytes(root):
    return {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in root.iterdir() if path.is_file()}


def verify(root, evidence):
    queue_path = root / ".kuzushi/v3/campaigns/rejected-context/queue.json"
    for _ in range(45):
        if queue_path.exists() and json.loads(queue_path.read_text())["jobs"]["context-001"]["state"] == "failed":
            break
        time.sleep(1)
    job = json.loads(queue_path.read_text())["jobs"]["context-001"]
    assert job["state"] == "failed" and job["attempts"] == 1
    run = root / ".kuzushi/v3/runs" / job["runId"]
    body = run.joinpath("rejected-context-output.txt").read_text()
    assert "LABELED_REJECTED_OUTPUT_1" in body and "LABELED_REJECTED_OUTPUT_2" in body
    assert len(body.encode()) <= 24 * 1024 + 1
    assert "LABELED_REJECTED_OUTPUT" not in run.joinpath("result.json").read_text()
    assert len((evidence / "rejected-provider-calls.jsonl").read_text().splitlines()) == 2
    assert not root.joinpath(".kuzushi/threat-models/manifest.json").exists()
    assert source_bytes(root) == json.loads((evidence / "source-before.json").read_text())
    with sqlite3.connect(root.joinpath(".kuzushi/v3/index.sqlite3").as_uri() + "?mode=ro", uri=True) as connection:
        assert connection.execute("select count(*) from investigation_call_reservations").fetchone()[0] == 2
        assert connection.execute("select count(*) from investigation_work_attempts").fetchone()[0] == 1
    (evidence / "rejected-context-check.json").write_text(json.dumps({"interceptedRequests": 2, "liveRequests": 0, "attempts": 1, "contextAccepted": False, "sourceUnchanged": True}, indent=2) + "\n")


def damage_input(root):
    queue = json.loads(root.joinpath(".kuzushi/v3/campaigns/rejected-context/queue.json").read_text())
    run = queue["jobs"]["context-001"]["runId"]
    root.joinpath(".kuzushi/v3/runs", run, "input.json").write_text(json.dumps({"model": "labeled-foreign-model"}))


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    elif stage == "damage":
        damage_input(root)
    else:
        verify(root, evidence)
