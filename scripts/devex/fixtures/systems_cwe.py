"""Owned CWE planning metadata. Intercepted transport, no source execution."""
import hashlib
import json
import shutil
import sys
import time
from pathlib import Path

import taint_catalog as base
from secret_settings import ledger, save

TOOL = "systems-hunt:deep-semantic-cwe-select"
INVESTIGATION = "owned-cwe-proposals"


def seed(root, evidence, home):
    base.seed(root, evidence, home)
    shutil.copyfile(Path(__file__).with_name("systems_cwe_provider.mjs"), evidence / "provider.mjs")
    base.command(evidence, "approval", "campaign:approve-allowance", {
        "investigationId": INVESTIGATION, "expectedRevision": 0, "model": base.MODEL,
        "maxProviderCalls": 2, "protectedReviewCalls": 0,
        "reason": "Two separate intercepted CWE proposal requests, invalid then valid. No live inference, tools, source execution, scans or follow-up jobs."})
    base.command(evidence, "unbound", TOOL, {"headBytes": 32})
    for name in ["invalid", "generate", "exhausted"]:
        base.command(evidence, name, TOOL, {"head_bytes": 32, "max_files": 1,
            "max_source_bytes": 128, "threatModelRef": None,
            "allowanceRef": {"schemaVersion": 1, "investigationId": INVESTIGATION,
                "revision": 1, "workId": "cwe-" + name}})
    base.command(evidence, "status", "campaign:allowance", {"investigationId": INVESTIGATION})


def modeled_results(root, count):
    for _ in range(80):
        rows = [(run, body) for run, body in base.results(root, TOOL)
                if "frozenInput" in body.get("data", {})]
        if len(rows) >= count:
            return rows
        time.sleep(0.25)
    raise AssertionError("Expected the saved proposal result")


def inspect(root, evidence, stage):
    expected = 0 if stage == "unbound" else (1 if stage == "invalid" else 2)
    calls = base.calls(evidence)
    assert len(calls) == expected
    assert all(row["tools"] == row["liveProviderRequests"] == 0 and row["freshSession"] for row in calls)
    baseline = json.loads((evidence / "baseline.json").read_text())
    assert hashlib.sha256(Path(baseline["path"]).read_bytes()).hexdigest() == baseline["sha256"]
    assert hashlib.sha256((root / "owned café.c").read_bytes()).hexdigest() == baseline["sourceSha256"]
    with ledger(root, evidence) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        assert {"finding_observations", "review_decisions"} <= tables
        if "investigation_call_reservations" not in tables:
            assert stage == "unbound"
        counts = {table: (db.execute("select count(*) from " + table).fetchone()[0] if table in tables else 0)
                  for table in ["finding_observations", "review_decisions", "investigation_call_reservations"]}
        assert counts["finding_observations"] == counts["review_decisions"] == 0
        assert counts["investigation_call_reservations"] == expected
        rows = db.execute("select call_json, review, settled_at from investigation_call_reservations") if expected else []
        for raw, review, settled in rows:
            assert json.loads(raw)["work"] == "scope" and review == 0 and settled is not None
    if stage == "invalid":
        output = modeled_results(root, 1)[-1][1]
        assert output["status"] == "failed" and not output["data"]["cwes"]
        assert "No repair request" in output["output"]
    if stage in ["generated", "restarted"]:
        run, output = modeled_results(root, 2)[-1]
        assert output["status"] == "partial" and output["data"]["sourceCheckCurrent"]
        assert output["data"]["cwes"][0]["id"] == "CWE-20"
        assert output["data"]["inspection"]["maxSourceFiles"] == 1
        assert output["data"]["inspection"]["maxFileBytes"] == 32
        assert output["data"]["inspection"]["truncatedSourceFiles"] == 1
        assert output["data"].get("costUsd") is None and not output["data"]["costUsdExact"]
        assert output["data"]["providerSpendUnresolved"] is True
        frozen = output["data"]["frozenInput"]
        assert frozen["selectedThreatModelRef"] is None and frozen["threatModel"] is None
        assert len(frozen["sources"]) == 1 and "owned_input" in frozen["sources"][0]["text"]
        assert output["data"]["accepted"] is False
        (evidence / "replay-command.txt").write_text("replay " + run["runId"])
        save(evidence, "proposal", {"runId": run["runId"], "treeHash": output["data"]["treeHash"]})
    assert not (root / ".kuzushi/v3/campaigns").exists()
    assert not (root / ".kuzushi/systems-hunt").exists()
    save(evidence, stage + "-check", {"interceptedRequests": expected, "liveProviderRequests": 0,
        "sourceExecuted": False, "sourceAndCatalogUnchanged": True,
        "counts": counts, "newJobs": 0})


if __name__ == "__main__":
    root, evidence = map(Path, sys.argv[1:3])
    stage = sys.argv[3]
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]))
    else:
        inspect(root, evidence, stage)
