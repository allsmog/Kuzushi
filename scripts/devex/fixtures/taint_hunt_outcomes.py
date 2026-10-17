"""Malformed model review retains owned structural metadata without completing Scan."""
import json
import shutil
import sys
import time
from pathlib import Path

import taint_catalog as base
from rejected_context import execute, source_bytes
from secret_settings import ledger, save

TOOL = "taint-iris-next:hunt"
INVESTIGATION = "owned-taint-hunt-outcomes"


def seed(root, evidence, home):
    base.seed(root, evidence, home)
    (root / "owned café.c").unlink()
    (root / "owned.ts").write_text("// Owned literal metadata only. Never executed.\nconst owned_value = owned_input();\nowned_sink(owned_value);\n")
    shutil.copyfile(Path(__file__).with_name("taint_hunt_outcomes_provider.mjs"), evidence / "provider.mjs")
    execute(root, home, evidence, "prepared-context", "context:build", {"enrichment": False})
    save(evidence, "source-before", source_bytes(root))
    supplied = {"mode": "hunt", "backend": "structural", "mcps": False,
        "discoverSignals": False, "catalogDigestRef": "static", "threatModelRef": None,
        "allowDeterministicFallback": True, "minEvidenceLevel": "linked", "cweFocus": ["CWE-20"],
        "maxCatalogEntries": 1, "maxAgentFindings": 1,
        "extraCatalogEntries": [{"cwe": "CWE-20", "name": "Owned literal markers",
            "taintClass": "owned-metadata", "languages": ["typescript", "javascript"],
            "sourceSignals": ["owned_input"], "sinkSignals": ["owned_sink"],
            "sanitizerSignals": [], "structuralQueries": [], "regexMarkers": []}]}
    base.command(evidence, "unbound", TOOL, supplied)
    base.command(evidence, "approval", "campaign:approve-allowance", {
        "investigationId": INVESTIGATION, "expectedRevision": 0, "model": base.MODEL,
        "maxProviderCalls": 3, "protectedReviewCalls": 1,
        "reason": "Owned intercepted initial and repair Discovery sessions, malformed output. Explicit structural candidate retention. No live inference, source execution or follow-up jobs. One protected Review call creates no Review job."})
    for name in ["invalid", "exhausted"]:
        base.command(evidence, name, TOOL, {**supplied, "allowanceRef": {
            "schemaVersion": 1, "investigationId": INVESTIGATION, "revision": 1, "workId": "hunt-" + name}})
    base.command(evidence, "status", "campaign:allowance", {"investigationId": INVESTIGATION})


def modeled_result(root):
    for _ in range(100):
        rows = [(run, body) for run, body in base.results(root, TOOL)
                if body.get("data", {}).get("agentStatus") == "invalid-json"]
        if rows:
            return rows[-1]
        time.sleep(0.2)
    raise AssertionError("Expected retained malformed model result")


def inspect(root, evidence, stage):
    calls = base.calls(evidence)
    expected = 0 if stage == "unbound" else 2
    assert len(calls) == expected, calls
    assert source_bytes(root) == json.loads((evidence / "source-before.json").read_text())
    assert all(row["liveProviderRequests"] == row["toolCalls"] == 0 and row["freshSession"] for row in calls)
    with ledger(root, evidence) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        counts = {table: db.execute("select count(*) from " + table).fetchone()[0] if table in tables else 0
                  for table in ["finding_observations", "review_decisions", "investigation_call_reservations"]}
        assert counts["investigation_call_reservations"] == expected
        assert counts["review_decisions"] == 0
        if expected:
            run, output = modeled_result(root)
            data = output["data"]
            assert output["status"] == run["status"] == "failed", (run, output)
            assert output["ok"] is False and data["structuredOutputValid"] is False
            assert data["structuredOutputRetryCount"] == 1
            assert len(data["findings"]) == len(data["reviewCandidates"]) == counts["finding_observations"] == 1
            assert data["stats"]["totalFindings"] == 0 and data["stats"]["totalReviewCandidates"] == 1
            assert output["output"].startswith("Model review failed. Scan is incomplete.")
            assert "hunt complete" not in output["output"]
            assert output["providerSpendUnresolved"] is True and output.get("costUsd") is None
            finding_run = data["persisted"]["runId"]
            assert db.execute("select status from run_states where run_id=?", [finding_run]).fetchone()[0] == "failed"
            for raw, review, settled in db.execute("select call_json, review, settled_at from investigation_call_reservations"):
                assert json.loads(raw)["work"] == "discovery" and review == 0 and settled is not None
            (evidence / "replay-command.txt").write_text("replay " + run["runId"])
            save(evidence, "failed-attempt", {"runId": run["runId"], "findingRunId": finding_run,
                "candidateCount": 1, "structuredOutputValid": False, "status": "failed"})
    if stage in ["exhausted", "restarted"]:
        blocked = [body for run, body in base.results(root, TOOL)
                   if run["status"] == "blocked" and "allowance exhausted" in body.get("summary", "")]
        assert len(blocked) == 1, blocked
    assert not (root / ".kuzushi/v3/campaigns").exists()
    assert not (root / ".kuzushi/cpg-rs").exists()
    save(evidence, stage + "-check", {"interceptedRequests": expected, "liveProviderRequests": 0,
        "counts": counts, "newJobs": 0, "sourceExecuted": False, "sourceUnchanged": True})


if __name__ == "__main__":
    root, evidence = map(Path, sys.argv[1:3])
    if sys.argv[3] == "seed":
        seed(root, evidence, Path(sys.argv[4]))
    else:
        inspect(root, evidence, sys.argv[3])
