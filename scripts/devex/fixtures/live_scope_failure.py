"""Read the terminal real-model scope failure. Never repeats or executes source."""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from secret_settings import ledger

FIXTURE = Path("/private/tmp/kuzushi-live-monorepo-scope-20261014")
CAMPAIGN = "live-scope-proposal-20261014"
MODEL = "openai-codex:gpt-6-luna"
RUN = CAMPAIGN + "-context-001-a1"


def saved(root):
    state = root / ".kuzushi/v3"
    paths = [state / "campaigns" / CAMPAIGN / leaf for leaf in ["plan.json", "queue.json"]]
    paths += [state / "runs" / RUN / leaf for leaf in ["run.json", "result.json", "input.json", "items.jsonl"]]
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}


def verify(root, evidence, stage):
    assert root == FIXTURE / "target"
    control = FIXTURE / "control"
    source = json.loads((control / "source-before.json").read_text())
    assert len(source) == 9
    assert all(hashlib.sha256((root / name).read_bytes()).hexdigest() == digest for name, digest in source.items())
    state = root / ".kuzushi/v3"
    assert len(list((state / "campaigns").glob("*/queue.json"))) == 1
    queue = json.loads((state / "campaigns" / CAMPAIGN / "queue.json").read_text())["jobs"]
    assert len(queue) == 1
    job = queue["context-001"]
    assert job["state"] == "failed" and job["attempts"] == job["dispatches"] == 1
    run = json.loads((state / "runs" / RUN / "run.json").read_text())
    assert run["status"] == "failed" and run["model"] == MODEL
    assert len(run["llmCalls"]) == 1 and run["llmCalls"][0]["callAttempted"]
    assert run["error"] == "unknown shared dependency greeting"
    with ledger(root, evidence) as db:
        assert db.execute("select count(*) from investigation_call_reservations").fetchone()[0] == 1
        assert db.execute("select count(*) from investigation_work_attempts").fetchone()[0] == 1
        assert db.execute("select count(*) from investigation_call_reservations where settled_at is null").fetchone()[0] == 0
        assert db.execute("select observed_usd from investigation_call_reservations").fetchone()[0] is None
    baseline = evidence / "historical-receipts-before.json"
    if stage == "inspect":
        assert not baseline.exists()
        baseline.write_text(json.dumps(saved(root), indent=2) + "\n")
    else:
        assert saved(root) == json.loads(baseline.read_text())
    inspect_original(root, evidence, stage)
    receipt = {"sourceFilesUnchanged":9, "sourceExecuted":False, "committedRequests":1,
        "aggregateRequestsIncludingPriorTests":7, "unresolvedRequests":0, "attempts":1,
        "status":"failed", "dollars":"unknown", "newWorkStarted":False, "historicalReceiptsUnchanged":True}
    (evidence / (stage + "-check.json")).write_text(json.dumps(receipt, indent=2) + "\n")


def inspect_original(root, evidence, stage):
    env = dict(os.environ, HOME=str(FIXTURE / "home"))
    for key in ["NODE_OPTIONS", "KUZUSHI_MODEL", "KUZUSHI_LANGGRAPH_BRIDGE", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"]:
        env.pop(key, None)
    result = subprocess.run([env["KUZUSHI_NATIVE_BIN"], "--plain", "--target", str(root),
        "run", "pack:scopes", "--input", '{"operation":"latest"}'], env=env, capture_output=True, text=True, timeout=30)
    (evidence / (stage + "-scopes-result.json")).write_text(result.stdout)
    assert result.returncode == 0, result.stderr
    review = json.loads(result.stdout)["data"]["review"]
    assert review["reference"]["revision"] == 1 and review["record"]["acceptance"] is None
    assert review["record"].get("generation") is None
    assert review["coverage"]["enumeratedFiles"] == 9 and review["coverage"]["uncoveredFiles"]["total"] == 0


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    verify(root, evidence, sys.argv[3])
