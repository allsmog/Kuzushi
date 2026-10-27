"""Inspect the recorded scope variant without approving or starting more work."""
import hashlib
import json
import sqlite3
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
CONTROL = REPO / "scripts/devex/artifacts/scope-context-variant-current-20261026/control"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(evidence, stage):
    prepared = json.loads((CONTROL / "prepared.json").read_text())
    live = json.loads((CONTROL / "live-result.json").read_text())
    root = Path(prepared["target"])
    state = root / ".kuzushi/v3"
    source = json.loads((CONTROL / "source-hashes.json").read_text())
    assert len(source) == 602
    assert all(digest(root / name) == sha for name, sha in source.items())
    campaign = state / "campaigns" / prepared["campaign"]
    assert digest(campaign / "plan.json") == prepared["planFileSha256"]
    job = json.loads((campaign / "queue.json").read_text())["jobs"]["context-001"]
    assert job["state"] == "completed" and job["attempts"] == job["dispatches"] == 1
    run = state / "runs" / live["runId"]
    result = json.loads((run / "result.json").read_text())["data"]
    assert result["reference"] == live["scopeReference"]
    record = result["record"]
    assert record["revision"] == 2 and record.get("acceptance") is None
    assert len(record["draft"]["scopes"]) == 7
    assert record["draft"]["sharedScope"]["id"] == "shared-contracts"
    assert record["draft"]["sharedDiscovery"] is False
    assert result["coverage"]["uncoveredFiles"] == {
        "files": ["workspace.json"], "total": 1}
    revisions = sorted((state / "scan-scopes/revisions").glob("*.json"))
    assert len(revisions) == 2
    assert all(json.loads(path.read_text()).get("acceptance") is None for path in revisions)
    manifest = root / ".kuzushi/threat-models/manifest.json"
    assert digest(manifest) == prepared["contextManifestSha256"]
    assert json.loads(manifest.read_text()).get("active") is None
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
        assert len(approvals) == len(calls) == len(work) == 2
        limits = [json.loads(row["approval_json"])["limits"]["maxProviderCalls"]
            for row in approvals]
        assert sorted(limits) == [1, 2]
        assert all(row["settled_at"] is not None and row["observed_usd"] is None
            and row["cost_complete"] == 0 for row in calls)
    immutable = [campaign / "plan.json", campaign / "queue.json", manifest, config]
    immutable += list((state / "scan-scopes").rglob("*.json"))
    for campaign_id in ["monorepo-scope-current-20261026", prepared["campaign"]]:
        immutable += list((state / "runs" / (campaign_id + "-context-001-a1")).glob("*"))
    hashes = {str(path): digest(path) for path in immutable if path.is_file()}
    before = evidence / "recorded-state-before.json"
    if stage == "inspect":
        assert not before.exists()
        before.write_text(json.dumps(hashes, indent=2) + "\n")
        request = {"investigationId": prepared["investigation"], "runId": live["runId"]}
        (evidence / "read-allowance.txt").write_text(
            "run campaign:allowance " + json.dumps(request))
    else:
        assert hashes == json.loads(before.read_text())
    value = {"sourceFilesUnchanged": 602, "primaryScopes": 7,
        "sharedContextScopes": 1, "discoveryFiles": 601, "uncoveredFiles": ["workspace.json"],
        "acceptedScopes": 0, "scopeRevision": 2, "contextActive": False,
        "providerRequestsBeforeInspection": 2, "providerRequestsAdded": 0,
        "cumulativeExperimentRequests": 19, "remainingAllowance": 0,
        "dollarCost": "unknown", "findingObservations": 0, "humanDecisions": 0,
        "networkFetchAttemptsDuringInspection": 0, "recordedStateUnchanged": True}
    (evidence / (stage + "-check.json")).write_text(json.dumps(value, indent=2) + "\n")


if __name__ == "__main__":
    evidence, stage = sys.argv[1:]
    verify(Path(evidence).resolve(), stage)
