"""Owned scoped source-only discovery with intercepted transport. No source execution."""
import hashlib
import json
import shutil
import sys
import time
from pathlib import Path

import taint_catalog as base
from rejected_context import execute
from secret_settings import ledger, save

TOOL = "systems-hunt:deep-semantic-hunt"
INVESTIGATION = "owned-deep-discovery"
FILES = ["app/owned.c", "other/hidden.c", "shared/context.md", "loose.c"]


def hashes(root):
    return {path: hashlib.sha256((root / path).read_bytes()).hexdigest() for path in FILES}


def scope(scope_id, path):
    return {"id": scope_id, "name": scope_id, "paths": [path],
            "rationale": "Owned source-only fixture boundary", "sharedDependencies": [], "openQuestions": []}


def seed(root, evidence, home):
    base.seed(root, evidence, home)
    for directory in ["app", "other", "shared"]:
        (root / directory).mkdir()
    (root / "owned café.c").rename(root / "app/owned.c")
    (root / "other/hidden.c").write_text("// owned_unapproved source; never executed\n")
    (root / "loose.c").write_text("// owned_loose_root source; never executed\n")
    (root / "shared/context.md").write_text("Owned shared context only; never executed.\n")
    shutil.copyfile(Path(__file__).with_name("systems_deep_provider.mjs"), evidence / "provider.mjs")
    draft = {"schemaVersion": 1, "scopes": [scope("app", "app"), scope("other", "other"),
             scope("integration", "shared"), scope("root", "loose.c")],
             "sharedScope": scope("shared", "shared"), "sharedDiscovery": False, "exclusions": []}
    proposed = execute(root, home, evidence, "scope-created", "pack:scopes", {"draft": draft})
    accepted = execute(root, home, evidence, "scope-accepted", "pack:scopes", {
        "operation": "accept", "proposalRef": proposed["reference"],
        "acknowledgements": {"inventoryLimitations": True, "exclusions": False, "overlappingDiscovery": False}})
    reference = {"proposal": accepted["reference"], "scopeId": "app"}
    save(evidence, "source-before", hashes(root))
    save(evidence, "scope-reference", reference)
    base.command(evidence, "approval", "campaign:approve-allowance", {
        "investigationId": INVESTIGATION, "expectedRevision": 0, "model": base.MODEL,
        "maxProviderCalls": 4, "protectedReviewCalls": 1,
        "reason": "Three separately invoked intercepted scoped discovery requests: invalid output, withheld capture, then valid. One protected Review call. No live inference, source execution, implicit class selection, repair or follow-up jobs."})
    base.command(evidence, "unbound", TOOL, {"cwes": ["CWE-20"]})
    for name in ["missing-classes", "invalid", "capture-limited", "generate", "exhausted"]:
        value = {"head_bytes": 32, "max_files": 2, "max_source_bytes": 128, "maxFindings": 1,
                 "cwes": ["CWE-20"], "scanScopeRef": reference, "scanContextRef": None, "threatModelRef": None,
                 "allowanceRef": {"schemaVersion": 1, "investigationId": INVESTIGATION,
                                  "revision": 1, "workId": "deep-" + name}}
        if name == "missing-classes":
            del value["cwes"]
        if name == "capture-limited":
            value["maxSnapshotBytes"] = 1
        base.command(evidence, name, TOOL, value)
    base.command(evidence, "status", "campaign:allowance", {"investigationId": INVESTIGATION})


def modeled_results(root, count):
    for _ in range(80):
        rows = [(run, body) for run, body in base.results(root, TOOL) if "frozenInput" in body.get("data", {})]
        if len(rows) >= count:
            return rows
        time.sleep(0.25)
    raise AssertionError("Expected saved discovery result")


def inspect(root, evidence, stage):
    expected = {"unbound": 0, "missing-classes": 0, "invalid": 1, "capture-limited": 2}.get(stage, 3)
    calls = base.calls(evidence)
    assert len(calls) == expected
    assert all(row["tools"] == row["liveProviderRequests"] == 0 and row["freshSession"] for row in calls)
    assert hashes(root) == json.loads((evidence / "source-before.json").read_text())
    baseline = json.loads((evidence / "baseline.json").read_text())
    assert hashlib.sha256(Path(baseline["path"]).read_bytes()).hexdigest() == baseline["sha256"]
    generated = stage in ["generated", "inputs-read", "decided", "exhausted", "restarted"]
    with ledger(root, evidence) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        assert {"finding_observations", "review_decisions"} <= tables
        counts = {table: (db.execute("select count(*) from " + table).fetchone()[0] if table in tables else 0)
                  for table in ["finding_observations", "review_decisions", "investigation_call_reservations"]}
        assert counts["finding_observations"] == int(generated)
        assert counts["review_decisions"] == int(stage in ["decided", "exhausted", "restarted"])
        assert counts["investigation_call_reservations"] == expected
        rows = db.execute("select call_json, review, settled_at from investigation_call_reservations") if expected else []
        for raw, review, settled in rows:
            assert json.loads(raw)["work"] == "discovery" and review == 0 and settled is not None
    if stage == "invalid":
        result = modeled_results(root, 1)[-1][1]
        assert result["status"] == "failed" and not result["data"]["findings"]
    if stage == "capture-limited":
        run, result = modeled_results(root, 2)[-1]
        assert result["status"] == "partial" and result["data"]["publicationStatus"] == "withheld"
        assert result["data"]["partialLedgerPossible"] is False
        assert not result["data"]["findings"] and len(result["data"]["unpublishedCandidates"]) == 1
        assert "Source capture refused publication" in result["summary"]
        assert "Inspect unpublished candidates in Replay" in result["output"]
        assert "HISTORICAL CANDIDATE OUTPUT" in result["output"]
        assert "Review observations in the findings ledger" not in result["output"]
        assert result["data"]["frozenInput"]["sources"]
        (evidence / "capture-replay-command.txt").write_text("replay " + run["runId"])
    if generated:
        run, result = modeled_results(root, 3)[-1]
        assert result["status"] == "partial" and result["data"]["sourceCheckCurrent"]
        assert result["data"]["count"] == 1 and result["data"]["findings"][0]["file_path"] == "app/owned.c"
        evidence_rows = result["data"]["findings"][0]["evidence"]
        assert [row["kind"] for row in evidence_rows] == ["model-claim-unscored", "source-citation-unscored", "source-citation-unscored"]
        assert all(row["confidence"] == 0 for row in evidence_rows)
        assert "owned_input" in evidence_rows[1]["snippet"]
        assert "context only" in evidence_rows[2]["rationale"]
        assert result["data"].get("costUsd") is None and not result["data"]["costUsdExact"]
        assert result["data"]["providerSpendUnresolved"] is True
        sources = result["data"]["frozenInput"]["sources"]
        assert "FROZEN MODEL INPUT" not in result["output"]
        document = result["data"]["inputDocument"]
        assert document["schemaVersion"] == 1
        assert "FROZEN MODEL INPUT" in document["text"]
        assert result["data"]["systemPrompt"] in document["text"]
        assert all(row["text"] in document["text"] for row in sources)
        assert {row["path"]: row["role"] for row in sources} == {"app/owned.c": "discovery", "shared/context.md": "context only"}
        assert result["data"]["inspection"]["scope"]["reference"] == json.loads((evidence / "scope-reference.json").read_text())
        assert result["data"]["inspection"]["maxSourceFiles"] == 2
        assert result["data"]["inspection"]["maxFileBytes"] == 32
        publication = result["data"]["publicationSource"]
        assert publication["kind"] == "authenticated captured files"
        assert publication["snapshotHash"] == result["data"]["snapshotHash"]
        assert publication["treeHash"] == result["data"]["treeHash"]
        assert publication["capturedFiles"] == 2
        assert publication["maxSnapshotBytes"] == 16 * 1024 * 1024
        assert publication["capturedBytes"] == sum(len((root / row["path"]).read_bytes()) for row in sources)
        assert result["output"].startswith("Review observations in the findings ledger")
        assert "Retained source: 2 cited files" in result["output"]
        assert "capture limit 16 MiB" in result["output"]
        with ledger(root, evidence) as db:
            snapshot, blob = db.execute("select snapshot_hash, blob_hash from finding_observations").fetchone()
        assert snapshot == result["data"]["snapshotHash"]
        objects = root / ".kuzushi/v3/objects/blake3"
        object_path = lambda value: objects / value[:2] / value[2:4] / value
        assert object_path(blob).read_bytes() == (root / "app/owned.c").read_bytes()
        tree = json.loads(object_path(publication["treeHash"]).read_text())
        memberships = {entry["name"]: entry["hash"] for entry in tree["entries"]}
        assert memberships["app/owned.c"] == blob
        for row in sources:
            assert object_path(memberships[row["path"]]).read_bytes() == (root / row["path"]).read_bytes()
        assert len(result["data"]["artifacts"]) == 1
        (evidence / "replay-command.txt").write_text("replay " + run["runId"])
    assert not (root / ".kuzushi/v3/campaigns").exists()
    save(evidence, stage + "-check", {"interceptedRequests": expected, "liveProviderRequests": 0,
        "sourceExecuted": False, "sourceAndCatalogUnchanged": True, "counts": counts,
        "newJobs": 0, "protectedReviewUnused": True, "capturedSourceVerified": generated})


if __name__ == "__main__":
    root, evidence = map(Path, sys.argv[1:3])
    if sys.argv[3] == "seed":
        seed(root, evidence, Path(sys.argv[4]))
    else:
        inspect(root, evidence, sys.argv[3])
