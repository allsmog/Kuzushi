"""Authenticate one failed live scope job without granting further work."""
import hashlib
import json
import sqlite3
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
CONTROL = REPO / "scripts/devex/artifacts/scope-proposal-current-20261026/control"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(evidence, stage):
    prepared = json.loads((CONTROL / "prepared.json").read_text())
    root = Path(prepared["target"])
    source = json.loads((CONTROL / "source-hashes.json").read_text())
    assert len(source) == 602
    assert all(digest(root / name) == sha for name, sha in source.items())
    state = root / ".kuzushi/v3"
    campaign = state / "campaigns" / prepared["campaign"]
    assert digest(campaign / "plan.json") == prepared["planFileSha256"]
    queue = json.loads((campaign / "queue.json").read_text())
    assert len(queue["jobs"]) == 1
    job = queue["jobs"]["context-001"]
    assert job["state"] == "failed" and job["attempts"] == job["dispatches"] == 1
    assert len(job["attemptRuns"]) == 1
    run_id = prepared["campaign"] + "-context-001-a1"
    run = state / "runs" / run_id
    record = json.loads((run / "run.json").read_text())
    assert record["status"] == "failed" and record["model"] == prepared["model"]
    assert record["providerSpendUnresolved"]
    assert len(record["llmCalls"]) == 1 and record["llmCalls"][0]["callAttempted"]
    result = json.loads((run / "result.json").read_text())
    assert "scope control-panel references unknown scope id contracts" in result["data"]["error"]
    events = [json.loads(line)["item"] for line in (run / "items.jsonl").read_text().splitlines()]
    finished = [event for event in events if event["type"] == "model_call_finished"]
    assert len(finished) == 1
    assert finished[0]["usage"] == {"inputTokens": 6992, "outputTokens": 658}
    manifest = root / ".kuzushi/threat-models/manifest.json"
    assert digest(manifest) == prepared["contextManifestSha256"]
    assert json.loads(manifest.read_text()).get("active") is None
    scope_files = sorted((state / "scan-scopes/revisions").glob("*.json"))
    assert len(scope_files) == 1
    scope = json.loads(scope_files[0].read_text())
    assert scope["revision"] == 1 and scope.get("acceptance") is None
    assert scope.get("generation") is None
    config = Path(prepared["operatorHome"]) / ".kuzushi/v3/config.toml"
    assert digest(config) == prepared["operatorConfigFileSha256"]
    assert not (evidence / "denied-fetch.jsonl").exists()
    with sqlite3.connect((state / "index.sqlite3").as_uri() + "?mode=rw", uri=True) as db:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA query_only=ON")
        assert db.execute("select count(*) from finding_observations").fetchone()[0] == 0
        assert db.execute("select count(*) from review_decisions").fetchone()[0] == 0
        approvals = list(db.execute("select * from investigation_allowance_revisions"))
        calls = list(db.execute("select * from investigation_call_reservations"))
        work = list(db.execute("select * from investigation_work_attempts"))
        assert len(approvals) == len(calls) == len(work) == 1
        approval = json.loads(approvals[0]["approval_json"])
        assert approval["limits"] == {"maxProviderCalls": 1, "protectedReviewCalls": 0}
        assert approval["workPlan"]["planSha256"] == prepared["planSha256"]
        assert calls[0]["settled_at"] is not None and calls[0]["observed_usd"] is None
        assert calls[0]["cost_complete"] == 0 and work[0]["run_id"] == run_id
    value = {"sourceFilesUnchanged": 602, "failedJobs": 1, "attempts": 1,
        "providerRequests": 1, "cumulativeExperimentRequests": 18,
        "inputTokens": 6992, "outputTokens": 658, "dollarCost": "unknown",
        "acceptedScopes": 0, "contextActive": False, "scopeRevision": 1,
        "findingObservations": 0, "humanDecisions": 0, "newFollowUpJobs": 0,
        "networkFetchAttemptsDuringInspection": 0}
    (evidence / (stage + "-check.json")).write_text(json.dumps(value, indent=2) + "\n")


if __name__ == "__main__":
    evidence, stage = sys.argv[1:]
    verify(Path(evidence).resolve(), stage)
