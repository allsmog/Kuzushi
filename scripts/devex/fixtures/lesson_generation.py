"""Real bounded lesson executor with intercepted model transport and an owned greeting."""
import hashlib
import json
import os
import shutil
import sqlite3
import sys
import time
from pathlib import Path
from reviewed_lessons import prepare
from rejected_context import execute


def seed(root, evidence, home):
    prepare(root, evidence)
    repo = Path(__file__).resolve().parents[3]
    shutil.copyfile(repo / "scripts/devex/fixtures/lesson_provider.mjs", evidence / "provider.mjs")
    credentials = home / ".kuzushi/lesson-credentials.json"
    credentials.parent.mkdir(parents=True, exist_ok=True)
    credentials.write_text(json.dumps({"openai-codex": {"access": "offline-lesson-fixture", "expires": 99999999999999}}))
    credentials.chmod(0o600)
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    command = ["node", "--import", str(evidence / "provider.mjs"), str(repo / "scripts/langgraph-bridge.mjs")]
    config.write_text('model = "openai-codex:gpt-5.5"\n[runtime]\nthinking_level = "medium"\nlanggraph_bridge_command = '
        + json.dumps(command) + '\n[runtime.anthropic_oauth]\ncredentials_path = '
        + json.dumps(str(credentials)) + '\nallow_env_token = false\n')
    (evidence / "reason.txt").write_text("Reviewed the generated text and its historical source limitations.")


def verify(root, evidence, stage):
    plans = [json.loads(path.read_text()) for path in (root / ".kuzushi/v3/campaigns").glob("*/plan.json")]
    plans = [plan for plan in plans if plan.get("tool") == "findings:lesson-generate"]
    assert len(plans) == 1, plans
    plan = plans[0]
    assert plan["workers"] == 1 and len(plan["jobs"]) == 1
    frozen = plan["jobs"][0]["input"]
    assert "allowanceRef" not in frozen and frozen["originRef"]["decision"]["decision"]["author"] == "human"
    assert frozen["originRef"]["finding"]["findingId"] == frozen["findingId"]
    (evidence / "resume-command.txt").write_text("campaign " + plan["campaignId"])
    calls_path = evidence / "provider-calls.jsonl"
    if stage == "draft":
        assert not calls_path.exists()
        return
    queue = root / ".kuzushi/v3/campaigns" / plan["campaignId"] / "queue.json"
    for _ in range(45):
        if queue.exists() and all(job["state"] == "completed" for job in json.loads(queue.read_text())["jobs"].values()):
            break
        time.sleep(1)
    assert all(job["state"] == "completed" for job in json.loads(queue.read_text())["jobs"].values())
    calls = [json.loads(line) for line in calls_path.read_text().splitlines()]
    assert len(calls) == 1 and calls[0]["tools"] == 0 and calls[0]["liveProviderRequests"] == 0
    page = execute(root, Path(os.environ["HOME"]), evidence, "lessons-" + stage, "findings:lessons", {})
    assert len(page["rows"]) == 1
    record = page["rows"][0]["lesson"]
    assert record["content"]["title"] == "Labeled model lesson"
    assert record["generation"]["synthesisRequests"] == 1
    assert record["generation"]["model"] == frozen["model"]
    assert record["generation"]["model"].split(":")[-1] == "gpt-5.5"
    assert record["state"] == ("accepted" if stage in ["accepted", "restart"] else "draft")
    allowance = execute(root, Path(os.environ["HOME"]), evidence, "allowance-" + stage, "campaign:allowance", {"investigationId": plan["investigationId"]})
    assert allowance["allowance"]["committedCalls"] == 1
    assert allowance["allowance"]["limits"]["protectedReviewCalls"] == 1
    assert allowance["dollarCeilingEnforced"] is False
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
        assert db.execute("select count(*) from finding_observations").fetchone()[0] == 1
        assert db.execute("select count(*) from review_decisions").fetchone()[0] == 1
    assert hashlib.sha256((root / "hello.txt").read_bytes()).hexdigest() == (evidence / "source-before.sha256").read_text()
    before = json.loads((evidence / "active-before.json").read_text())
    assert hashlib.sha256(Path(before["path"]).read_bytes()).hexdigest() == before["sha256"]
    (evidence / (stage + "-check.json")).write_text(json.dumps({"stage": stage, "lessonState": record["state"],
        "lessonRef": page["rows"][0]["lessonRef"], "jobs": 1, "attempts": 1, "workers": 1,
        "interceptedRequests": 1, "liveProviderRequests": 0, "protectedReviewCalls": 1,
        "sourceExecuted": False, "sourceUnchanged": True, "activeContextUnchanged": True}, indent=2) + "\n")


if __name__ == "__main__":
    action, target, output, *homes = sys.argv[1:]
    root, evidence = Path(target).resolve(), Path(output).resolve()
    if action == "seed":
        seed(root, evidence, Path(homes[0]).resolve())
    else:
        verify(root, evidence, action)
