"""Owned historical request and revised limits. Intercepted transport only."""
import hashlib
import json
import sys
from pathlib import Path

import prepared_input_recovery as prepared
import systems_deep as discovery
import taint_catalog as catalog
from rejected_context import execute
from secret_settings import ledger, save


def request_path(root, evidence):
    run_id = prepared.calls(evidence)[0]["runId"]
    return root / ".kuzushi/v3/runs" / run_id / "input.json"


def check(root, evidence, stage):
    prepared.invariant(root, evidence, stage, 1)
    with ledger(root, evidence) as db:
        current = db.execute("select max(revision) from investigation_allowance_revisions").fetchone()[0]
        assert current == (1 if stage == "before" else 2)
        calls = list(db.execute("select revision, review, settled_at from investigation_call_reservations"))
        assert len(calls) == 1 and calls[0][0] == 1 and calls[0][1] == 0 and calls[0][2] is not None
    path = request_path(root, evidence)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    before = evidence / "recorded-request-hash.json"
    if stage == "before":
        save(evidence, "recorded-request-hash", {"sha256": digest})
    else:
        assert digest == json.loads(before.read_text())["sha256"]
    value = json.loads(path.read_text())
    assert value["allowanceRef"]["revision"] == 1
    assert value["scanScopeRef"]["scopeId"] == "app"
    save(evidence, stage + "-request-context", {
        "originalGrantRevision": 1, "latestGrantRevision": current,
        "committedCalls": 1, "protectedReviewUnused": True,
        "savedInputUnchanged": True, "liveProviderRequests": 0,
        "sourceUnchanged": True, "newJobs": 0})


def revise(root, evidence, home):
    execute(root, home, evidence, "revised-allowance", "campaign:approve-allowance", {
        "investigationId": discovery.INVESTIGATION, "expectedRevision": 1,
        "model": catalog.MODEL, "maxProviderCalls": 5, "protectedReviewCalls": 1,
        "reason": "Offline read-refresh fixture only. No additional calls or work will run."})
    check(root, evidence, "revised")


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    stage = sys.argv[3]
    if stage == "seed":
        prepared.seed(root, evidence, Path(sys.argv[4]).resolve())
    elif stage == "before":
        prepared.stopped(root, evidence, "failed", "failed", 1)
        check(root, evidence, stage)
    elif stage == "revise":
        revise(root, evidence, Path(sys.argv[4]).resolve())
    else:
        check(root, evidence, stage)
