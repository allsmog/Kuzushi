"""Accepted membership through native prepared scans and constrained reads. No live inference."""
import hashlib
import json
import shutil
import sqlite3
import sys
from pathlib import Path
from investigation_journey import seed, plans, wait_jobs, read_native
from rejected_context import execute


def source_hashes(root):
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for directory in ["app", "shared", "other"] for path in (root / directory).rglob("*.rs")}


def scope(name, path):
    return {"id": name, "name": name, "paths": [path], "rationale": "Owned scope workflow fixture",
            "sharedDependencies": [], "openQuestions": []}


def prepare(root, evidence, home):
    seed(root, evidence, home)
    for file in ["app.py", "main.rs", "config.env"]:
        (root / file).unlink()
    for directory in ["app/[route]", "shared", "other"]:
        (root / directory).mkdir(parents=True)
    for path, text in [("app/[route]/reader.rs", "// OWNED DISCOVERY\n"),
                       ("shared/context.rs", "// OWNED CONTEXT\n"),
                       ("other/unapproved.rs", "// UNAPPROVED SOURCE\n")]:
        (root / path).write_text(text)
    repo = Path(__file__).resolve().parents[3]
    shutil.copyfile(repo / "scripts/devex/fixtures/scoped_discovery_provider.mjs", evidence / "provider.mjs")
    created = execute(root, home, evidence, "scope-create", "pack:scopes", {"draft": {
        "schemaVersion": 1, "scopes": [scope("app", "app"), scope("other", "other"), scope("integration", "shared")],
        "sharedScope": scope("shared", "shared"), "sharedDiscovery": False, "exclusions": []}})
    accepted = execute(root, home, evidence, "scope-accept", "pack:scopes", {
        "operation": "accept", "proposalRef": created["reference"],
        "acknowledgements": {"inventoryLimitations": True, "exclusions": False, "overlappingDiscovery": False}})
    reference = {"proposal": accepted["reference"], "scopeId": "app"}
    (evidence / "scope-reference.json").write_text(json.dumps(reference))
    (evidence / "source-before.json").write_text(json.dumps(source_hashes(root)))
    draft = execute(root, home, evidence, "scan-plan", "campaign:study", {
        "campaignId": "scoped-study", "investigationId": "scoped-investigation", "trials": 3,
        "scanInput": {"taskMode": "manual", "tasks": ["agentic"], "scanScopeRef": reference,
            "threatModelRef": None, "scanContextRef": None, "maxInventoryFiles": 8,
            "maxBytesPerFile": 64, "maxIterations": 2, "mcps": False}})
    execute(root, home, evidence, "scan-approval", "campaign:approve-allowance", {
        "investigationId": "scoped-investigation", "expectedRevision": 0,
        "model": "openai-codex:gpt-5.5", "maxProviderCalls": 8, "protectedReviewCalls": 2,
        "reason": "Six intercepted source-only calls, including scoped read checks. No live inference.",
        "campaignId": "scoped-study", "campaignPlanSha256": draft["planSha256"],
        "campaignJobs": 3, "maxJobAttempts": 1})
    path = root / ".kuzushi/v3/workflow/phase-attempts.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"event": "phase_checkpoint_skipped", "phase": "map",
        "targetSnapshot": {"target": str(root), "dirty": False}, "recordedAtUnix": 1}) + "\n")


def verify(root, evidence):
    assert source_hashes(root) == json.loads((evidence / "source-before.json").read_text())
    plan = next(p for p in plans(root) if p["campaignId"] == "scoped-study")
    reference = json.loads((evidence / "scope-reference.json").read_text())
    assert len(plan["jobs"]) == 3 and plan["workers"] == 1
    assert all(job["input"]["scanScopeRef"] == reference for job in plan["jobs"])
    jobs = wait_jobs(root, plan, {"completed"})
    assert len(jobs) == 3 and all(job["attempts"] == 1 for job in jobs.values())
    calls = [json.loads(line) for line in (evidence / "scoped-discovery-calls.jsonl").read_text().splitlines()]
    assert len(calls) == 6 and len({row["bridgePid"] for row in calls}) == 3
    assert sum(row["contextReadAndOutsideDenied"] for row in calls) == 3
    scopes = []
    for job in jobs.values():
        parent = root / ".kuzushi/v3/runs" / job["runId"]
        result = json.loads((parent / "result.json").read_text())["data"]
        run_id = result["runIds"]["agentic"]
        data = json.loads((root / ".kuzushi/v3/runs" / run_id / "result.json").read_text())["data"]
        assert data["count"] == 1
        assert {row["file_path"] for row in data["outOfScopeObservations"]} == {"shared/context.rs", "other/unapproved.rs"}
        assert data["scope"]["discoveryFiles"] == 1 and data["scope"]["inheritedContextFiles"] == 1
        assert result["agentic"]["scope"] == data["scope"]
        scopes.append(data["scope"])
    assert len(scopes) == 3 and len({scope["readMembershipSha256"] for scope in scopes}) == 1
    occurrence = read_native(root, evidence, "occurrence", ["findings", "batch", "scoped-study", "--json"])
    assert len(occurrence["rows"]) == 1 and occurrence["rows"][0]["seen"] == 3
    (evidence / "open-finding.txt").write_text("open " + occurrence["rows"][0]["representativeFingerprint"])
    with sqlite3.connect(root / ".kuzushi/v3/index.sqlite3") as db:
        assert db.execute("select count(*) from investigation_call_reservations").fetchone()[0] == 6
        assert db.execute("select count(*) from investigation_call_reservations where settled_at is null").fetchone()[0] == 0
        assert db.execute("select count(*) from investigation_call_reservations where review=1").fetchone()[0] == 0
        approval = json.loads(db.execute("select approval_json from investigation_allowance_revisions order by revision desc limit 1").fetchone()[0])
        assert approval["limits"] == {"maxProviderCalls": 8, "protectedReviewCalls": 2}
        assert db.execute("select count(*) from finding_observations").fetchone()[0] == 3
    (evidence / "scoped-discovery-verified.json").write_text(json.dumps({"fixedJobs": 3,
        "committedCalls": 6, "protectedReviewCalls": 2, "constrainedReadChecks": 3,
        "acceptedObservations": 3, "retainedOutsideDiscovery": 6,
        "acceptedContextOmitted": True, "liveRequests": 0, "sourceExecuted": False}, indent=2))


def verify_narrow_report(evidence):
    bodies = []
    for path in sorted(evidence.glob("*-report-*40x12.txt")):
        rows = path.read_text().splitlines()
        footer = next(index for index, row in enumerate(rows) if row.startswith("⛭"))
        bodies.extend(rows[1:footer])
    text = " ".join(" ".join(bodies).split())
    for phrase in ["6 committed / 8 calls", "2 protected review remaining",
                   "observations outside discovery", "retained in the run receipt",
                   "no complete coverage claim"]:
        assert phrase in text, "Paged 40x12 report did not expose " + phrase


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    if sys.argv[3] == "seed":
        prepare(root, evidence, Path(sys.argv[4]).resolve())
    else:
        verify(root, evidence)
        if sys.argv[3] == "restarted":
            verify_narrow_report(evidence)
