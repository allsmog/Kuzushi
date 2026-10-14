"""One accepted file-group context request and durable scope draft recovery. No source execution."""
import hashlib
import json
import os
import shutil
import sqlite3
import sys
from pathlib import Path
from investigation_journey import seed, plans, wait_jobs
from rejected_context import execute
from context_comparison import import_context
from finite_scopes import scope


def sources(root):
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for directory in ["app", "adapter", "shared", "other"] for path in (root / directory).glob("*.rs")}


def prepare(root, evidence, home):
    seed(root, evidence, home)
    for name in ["main.rs", "app.py", "config.env"]:
        (root / name).unlink()
    for name in ["app", "adapter", "shared", "other"]:
        (root / name).mkdir()
    for path, text in [("app/reader.rs", "// OWNED APP\n"), ("adapter/entry.rs", "// OWNED ADAPTER\n"),
                       ("shared/context.rs", "// OWNED SHARED\n"), ("other/reader.rs", "// UNSELECTED SIBLING\n")]:
        (root / path).write_text(text)
    repo = Path(__file__).resolve().parents[3]
    shutil.copyfile(repo / "scripts/devex/fixtures/group_context_provider.mjs", evidence / "provider.mjs")
    group = scope("app", "app")
    group["paths"].append("adapter")
    created = execute(root, home, evidence, "group-scopes", "pack:scopes", {"draft": {
        "schemaVersion": 1, "scopes": [group, scope("other", "other"), scope("integration", "shared")],
        "sharedScope": scope("shared", "shared"), "sharedDiscovery": False, "exclusions": []}})
    execute(root, home, evidence, "group-accept", "pack:scopes", {"operation": "accept", "proposalRef": created["reference"],
        "acknowledgements": {"inventoryLimitations": True, "exclusions": False, "overlappingDiscovery": False}})
    active = import_context(os.environ["KUZUSHI_NATIVE_BIN"], root, evidence, "Beta")
    (evidence / "group-before.json").write_text(json.dumps({"active": active, "sources": sources(root)}))
    path = root / ".kuzushi/v3/workflow/phase-attempts.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"event": "phase_checkpoint_skipped", "phase": "map",
        "targetSnapshot": {"target": str(root), "dirty": False}, "recordedAtUnix": 1}) + "\n")


def verify(root, evidence, stage):
    before = json.loads((evidence / "group-before.json").read_text())
    manifest = json.loads((root / ".kuzushi/threat-models/manifest.json").read_text())
    assert manifest["active"] == before["active"] and sources(root) == before["sources"]
    entries = plans(root)
    context = [plan for plan in entries if plan["kind"] == "context-study"]
    assert len(context) == 1
    context = context[0]
    assert context["workers"] == 1 and len(context["jobs"]) == 1
    origin = context["scopeStudyOrigin"]
    assert origin["scopeCases"] == [{"scopeId": "app", "passes": 3}, {"scopeId": "other", "passes": 3, "threatModelRef": None}]
    assert origin["scanInput"]["threatModelRef"] == before["active"]
    job = context["jobs"][0]
    assert job["input"]["scanScopeRef"]["scopeId"] == "app"
    assert job["input"]["inheritedContextRef"] == before["active"]
    if stage == "draft":
        assert len(manifest["models"]) == 1 and not (evidence / "group-context-calls.jsonl").exists()
        return
    wait_jobs(root, context, {"completed"})
    manifest = json.loads((root / ".kuzushi/threat-models/manifest.json").read_text())
    calls = [json.loads(line) for line in (evidence / "group-context-calls.jsonl").read_text().splitlines()]
    assert len(calls) == 1 and len(manifest["models"]) == 2
    model = manifest["models"][-1]
    revision = model["revisions"][-1]
    reference = {"modelId": model["modelId"], "revisionId": revision["revisionId"], "sha256": revision["sha256"]}
    path = root / ".kuzushi/threat-models/objects" / ("sha256-" + reference["sha256"].removeprefix("sha256:") + ".json")
    receipt = json.loads(path.read_text())["provenance"]["scopeContext"]["receipt"]
    assert receipt["scopeRef"] == job["input"]["scanScopeRef"]
    assert receipt["synthesisRequests"] == 1 and not receipt["completeRepositoryCoverage"]
    files = receipt["sourceEvidence"]["files"]
    assert {file["path"] for file in files} == {"app/reader.rs", "adapter/entry.rs", "shared/context.rs"}
    assert [file["scopeRole"] for file in files].count("shared-context") == 1
    with sqlite3.connect(root / ".kuzushi/v3/index.sqlite3") as db:
        assert db.execute("select count(*) from investigation_call_reservations").fetchone()[0] == 1
        assert db.execute("select count(*) from investigation_call_reservations where settled_at is null or review=1").fetchone()[0] == 0
        approval = json.loads(db.execute("select approval_json from investigation_allowance_revisions order by revision desc limit 1").fetchone()[0])
        assert approval["limits"] == {"maxProviderCalls": 9, "protectedReviewCalls": 2}
        assert len(approval["workPlan"]["jobs"]) == 1
    (evidence / "group-resume.txt").write_text("campaign " + context["campaignId"])
    scans = [plan for plan in entries if plan["kind"] == "scope-study"]
    if stage == "planned":
        assert len(scans) == 1 and scans[0]["jobCount"] == 6
        selected = scans[0]["scopeStudy"]["selections"]
        assert selected[0]["threatModelRef"] == reference and selected[1]["threatModelRef"] is None
        assert scans[0]["investigationId"] == context["investigationId"]
        assert not (root / ".kuzushi/v3/campaigns" / scans[0]["campaignId"] / "queue.json").exists()
    else:
        assert not scans
    (evidence / ("group-context-" + stage + ".json")).write_text(json.dumps({
        "contextJobs": 1, "callsCommitted": 1, "protectedReview": 2, "modelRef": reference,
        "activeUnchanged": True, "sourceExecuted": False, "liveRequests": 0,
        "scansStarted": 0, "scopeDraftRestored": True}, indent=2))


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    if sys.argv[3] == "seed":
        prepare(root, evidence, Path(sys.argv[4]).resolve())
    else:
        verify(root, evidence, sys.argv[3])
