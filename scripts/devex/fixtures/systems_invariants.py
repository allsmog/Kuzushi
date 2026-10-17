"""Actual bounded context consumed by intercepted invariant drafts. No source execution."""
import hashlib
import json
import re
import shutil
import sys
import time
from pathlib import Path

import taint_catalog as base
from rejected_context import execute, source_bytes
from secret_settings import ledger, save

TOOL = "systems-hunt:systems-invariant-extract"
INVESTIGATION = "owned-invariant-context"


def seed(root, evidence, home):
    base.seed(root, evidence, home)
    (root / "owned café.c").write_text("// owned_input owned_sink memcpy guard; inert metadata, never executed.\n")
    (root / "zz context.c").write_text("// owned_omitted_context memcpy guard; inert metadata, never executed.\n")
    shutil.copyfile(Path(__file__).with_name("systems_invariants_provider.mjs"), evidence / "provider.mjs")
    context = execute(root, home, evidence, "bounded-context", "systems-hunt:systems-context-gatherer", {})
    assert len(context["surfaces"]) == 2, context
    assert context["surfaces"][0]["filePath"] == "owned café.c"
    save(evidence, "surface", {"id": context["surfaces"][0]["id"]})
    save(evidence, "source-before", source_bytes(root))
    supplied = {"context": context, "max_surfaces": 1, "max_files": 1, "head_bytes": 32,
                "max_source_bytes": 128, "threatModelRef": None}
    base.command(evidence, "unbound", TOOL, supplied)
    base.command(evidence, "approval", "campaign:approve-allowance", {
        "investigationId": INVESTIGATION, "expectedRevision": 0, "model": base.MODEL,
        "maxProviderCalls": 3, "protectedReviewCalls": 1,
        "reason": "Two separately invoked intercepted Context requests, invalid then valid. One protected Review call creates no Review job. No live inference or source execution."})
    for name in ["invalid", "generate", "exhausted"]:
        base.command(evidence, name, TOOL, {**supplied, "allowanceRef": {
            "schemaVersion": 1, "investigationId": INVESTIGATION, "revision": 1, "workId": "draft-" + name}})
    base.command(evidence, "status", "campaign:allowance", {"investigationId": INVESTIGATION})


def modeled_results(root, count):
    for _ in range(80):
        rows = [(run, body) for run, body in base.results(root, TOOL) if "frozenInput" in body.get("data", {})]
        if len(rows) >= count:
            return rows
        time.sleep(0.25)
    raise AssertionError("Expected retained invariant draft result")


def inspect(root, evidence, stage):
    expected = 0 if stage == "unbound" else 1 if stage == "invalid" else 2
    calls = base.calls(evidence)
    assert len(calls) == expected
    assert all(row["tools"] == row["liveProviderRequests"] == 0 and row["freshSession"] for row in calls)
    assert source_bytes(root) == json.loads((evidence / "source-before.json").read_text())
    with ledger(root, evidence) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        counts = {table: db.execute("select count(*) from " + table).fetchone()[0] if table in tables else 0
                  for table in ["finding_observations", "review_decisions", "investigation_call_reservations"]}
        assert counts["finding_observations"] == counts["review_decisions"] == 0
        assert counts["investigation_call_reservations"] == expected
        rows = db.execute("select call_json, review, settled_at from investigation_call_reservations") if expected else []
        for raw, review, settled in rows:
            assert json.loads(raw)["work"] == "context" and review == 0 and settled is not None
    if stage == "invalid":
        output = modeled_results(root, 1)[-1][1]
        assert output["status"] == "failed" and not output["data"]["invariants"]
        assert "No repair request" in output["output"]
        assert output["data"]["inputDocument"]["schemaVersion"] == 1
    if stage in ["generated", "exhausted", "restarted"]:
        run, output = modeled_results(root, 2)[-1]
        data = output["data"]
        assert output["status"] == "partial" and data["sourceCheckCurrent"]
        assert data["invariants"][0]["id"] == "owned-assumption"
        assert data["accepted"] is False and data.get("costUsd") is None and not data["costUsdExact"]
        assert data["providerSpendUnresolved"] is True
        assert data["inspection"]["includedSurfaces"] == 1 and len(data["inspection"]["omittedSurfaces"]) == 1
        assert data["frozenInput"]["supportingContext"]["selectedThreatModelRef"] is None
        assert len(data["frozenInput"]["sources"]) == 1
        assert all(set(anchor) == {"id", "filePath", "startLine"}
                   for anchor in data["frozenInput"]["surfaces"])
        assert "Lexical annotations" in data["inputDocument"]["text"]
        assert "owned_input" in data["inputDocument"]["text"]
        assert "FROZEN MODEL INPUT" not in output["output"]
        retained = json.loads((root / ".kuzushi/v3/runs" / run["runId"] / "prepared-model-input.json").read_text())
        assert retained["data"]["inputDocument"] == data["inputDocument"]
        (evidence / "replay-command.txt").write_text("replay " + run["runId"])
        save(evidence, "draft", {"runId": run["runId"], "treeHash": data["treeHash"]})
    if stage in ["exhausted", "restarted"]:
        blocked = [body for run, body in base.results(root, TOOL)
                   if run["status"] == "blocked" and "allowance exhausted" in body.get("summary", "")]
        assert len(blocked) == 1
    if stage == "narrow":
        inspect_narrow(evidence)
    assert not (root / ".kuzushi/v3/campaigns").exists()
    assert not (root / ".kuzushi/systems-hunt").exists()
    assert not (root / ".kuzushi/threat-models").exists()
    save(evidence, stage + "-check", {"interceptedRequests": expected, "liveProviderRequests": 0,
        "counts": counts, "newJobs": 0, "contextAccepted": False, "sourceExecuted": False})


def inspect_narrow(evidence):
    proof = {}
    for view, first, pages in [("Result", "result-40x12", "result-reading-*-40x12"),
                               ("Inputs", "inputs-start-40x12", "inputs-reading-*-40x12")]:
        paths = sorted(evidence.glob("*-" + pages + ".txt")) + list(evidence.glob("*-" + first + ".txt"))
        paths += list(evidence.glob("*-" + view.lower() + "-tail-40x12.txt"))
        covered, body, totals = set(), [], set()
        for path in paths:
            text = path.read_text()
            start, end, total = map(int, re.search(r"rows (\d+)-(\d+)/(\d+)", text).groups())
            assert "REPLAY · " + view in text
            covered.update(range(start, end + 1))
            totals.add(total)
            body.extend(text.splitlines()[2:7])
        assert len(totals) == 1
        total = totals.pop()
        assert covered == set(range(1, total + 1)), (view, sorted(set(range(1, total + 1)) - covered))
        joined = " ".join(" ".join(body).split())
        required = (["Review before accepting context", "Source: owned café.c:1",
                     "No findings, scan jobs, accepted context or phase completion",
                     "Complete repository coverage is not established", "Context allowance",
                     "Full coverage receipt is included in the result"] if view == "Result" else
                    ["Surface source: owned café.c:1", "Lexical annotations", "Source: owned café.c",
                     "owned_input owned_sink memcpy", "System instructions:", "not permission to execute"])
        assert all(phrase in joined for phrase in required), (view, [phrase for phrase in required if phrase not in joined])
        proof[view] = {"capturedPages": len(paths), "rowsCovered": total, "allRowsReached": True,
                       "requiredFactsReadable": required}
    save(evidence, "narrow-reading", proof)


if __name__ == "__main__":
    root, evidence = map(Path, sys.argv[1:3])
    if sys.argv[3] == "seed":
        seed(root, evidence, Path(sys.argv[4]))
    else:
        inspect(root, evidence, sys.argv[3])
