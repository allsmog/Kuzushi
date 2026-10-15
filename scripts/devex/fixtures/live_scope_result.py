"""Read the actual unaccepted scope proposal, coverage gaps and shared spending."""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from live_scope_failure import FIXTURE, MODEL, saved
from secret_settings import ledger

CAMPAIGN = "live-scope-proposal-references-20261014"
RUN = CAMPAIGN + "-context-001-a1"
PRIOR = Path("/tmp/kuzushi-tui-integration-20261012/live-scope-readable/20261014-162627/J261")


def verify(root, evidence, stage):
    assert root == FIXTURE / "target"
    source = json.loads((FIXTURE / "control/source-before.json").read_text())
    assert all(hashlib.sha256((root / name).read_bytes()).hexdigest() == digest for name, digest in source.items())
    assert saved(root) == json.loads((PRIOR / "historical-receipts-before.json").read_text())
    state = root / ".kuzushi/v3"
    assert len(list((state / "campaigns").glob("*/queue.json"))) == 2
    jobs = json.loads((state / "campaigns" / CAMPAIGN / "queue.json").read_text())["jobs"]
    assert len(jobs) == 1 and jobs["context-001"]["state"] == "completed"
    assert jobs["context-001"]["attempts"] == jobs["context-001"]["dispatches"] == 1
    run = json.loads((state / "runs" / RUN / "run.json").read_text())
    assert run["status"] == "completed" and run["model"] == MODEL
    assert len(run["llmCalls"]) == 1 and run["llmCalls"][0]["callAttempted"]
    review = json.loads((state / "runs" / RUN / "result.json").read_text())["data"]
    assert review["reference"]["revision"] == 2 and review["record"]["acceptance"] is None
    assert review["record"]["generation"]["runId"] == RUN and review["record"]["generation"]["contextRef"] is None
    coverage = review["coverage"]
    assert coverage["enumeratedFiles"] == 9 and coverage["uncoveredFiles"]["total"] == 2
    assert coverage["overlaps"]["total"] == 0 and coverage["excludedFiles"]["total"] == 0
    assert coverage["discoveryMembers"]["root-integration"]["files"] == ["Cargo.toml", "README.md", "ROOT-NOTES.md"]
    assert coverage["contextMembers"]["greeting-context"]["files"] == coverage["uncoveredFiles"]["files"]
    with ledger(root, evidence) as db:
        assert db.execute("select count(*) from investigation_call_reservations").fetchone()[0] == 2
        assert db.execute("select count(*) from investigation_work_attempts").fetchone()[0] == 2
        assert db.execute("select count(*) from investigation_call_reservations where settled_at is null").fetchone()[0] == 0
        assert db.execute("select count(*) from investigation_call_reservations where observed_usd is not null").fetchone()[0] == 0
    inspect_current(root, evidence, stage, review["reference"])
    receipt = {"unacceptedRevision":2, "sourceFilesUnchanged":9, "discoveryMembers":7,
        "uncoveredFiles":2, "sharedContextFiles":2, "overlappingFiles":0, "committedRequests":2,
        "aggregateRequestsIncludingPriorTests":8, "unresolvedRequests":0, "protectedReviewCalls":1,
        "remainingScopeOrScanCalls":0, "dollars":"unknown", "sourceExecuted":False,
        "scanJobsStarted":0, "originalFailureUnchanged":True}
    (evidence / (stage + "-check.json")).write_text(json.dumps(receipt, indent=2) + "\n")


def inspect_current(root, evidence, stage, reference):
    env = dict(os.environ, HOME=str(FIXTURE / "home"))
    for key in ["NODE_OPTIONS", "KUZUSHI_MODEL", "KUZUSHI_LANGGRAPH_BRIDGE", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"]:
        env.pop(key, None)
    result = subprocess.run([env["KUZUSHI_NATIVE_BIN"], "--plain", "--target", str(root),
        "run", "pack:scopes", "--input", '{"operation":"latest"}'], env=env, capture_output=True, text=True, timeout=30)
    (evidence / (stage + "-current-scopes.json")).write_text(result.stdout)
    assert result.returncode == 0, result.stderr
    current = json.loads(result.stdout)["data"]["review"]
    assert current["reference"] == reference and current["record"]["acceptance"] is None


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    verify(root, evidence, sys.argv[3])
