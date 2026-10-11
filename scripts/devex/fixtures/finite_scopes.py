"""Native operator-selected finite scopes. Intercepted transport; no source execution."""
import json
import shutil
import sqlite3
import sys
from pathlib import Path
from investigation_journey import seed, plans, wait_jobs, read_native
from rejected_context import execute
from scoped_discovery import scope, source_hashes


def prepare(root, evidence, home):
    seed(root, evidence, home)
    for name in ["main.rs", "app.py", "config.env"]:
        (root / name).unlink()
    for name in ["app", "other", "shared"]:
        (root / name).mkdir()
    for path, text in [("app/reader.rs", "// OWNED APP\n"), ("other/reader.rs", "// OWNED OTHER\n"),
                       ("shared/context.rs", "// OWNED SHARED\n")]:
        (root / path).write_text(text)
    repo = Path(__file__).resolve().parents[3]
    shutil.copyfile(repo / "scripts/devex/fixtures/finite_scopes_provider.mjs", evidence / "provider.mjs")
    created = execute(root, home, evidence, "scope-create", "pack:scopes", {"draft": {
        "schemaVersion": 1, "scopes": [scope("app", "app"), scope("other", "other"), scope("integration", "shared")],
        "sharedScope": scope("shared", "shared"), "sharedDiscovery": False, "exclusions": []}})
    execute(root, home, evidence, "scope-accept", "pack:scopes", {
        "operation": "accept", "proposalRef": created["reference"],
        "acknowledgements": {"inventoryLimitations": True, "exclusions": False, "overlappingDiscovery": False}})
    (evidence / "source-before.json").write_text(json.dumps(source_hashes(root)))
    path = root / ".kuzushi/v3/workflow/phase-attempts.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"event": "phase_checkpoint_skipped", "phase": "map",
        "targetSnapshot": {"target": str(root), "dirty": False}, "recordedAtUnix": 1}) + "\n")


def selected_plan(root, evidence):
    entries = [entry for entry in plans(root) if entry["kind"] == "scope-study"]
    assert len(entries) == 1
    plan = entries[0]
    assert plan["workers"] == 1 and plan["jobCount"] == 6 and len(plan["jobs"]) == 6
    assert {entry["id"] for entry in plan["scopeStudy"]["cases"]} == {"app", "other"}
    assert plan["scopeStudy"]["unplannedScopeIds"] == ["integration"]
    (evidence / "campaign-command.txt").write_text("campaign " + plan["campaignId"])
    return plan


def verify(root, evidence, stage):
    plan = selected_plan(root, evidence)
    assert source_hashes(root) == json.loads((evidence / "source-before.json").read_text())
    calls_path = evidence / "finite-scope-calls.jsonl"
    if stage == "draft":
        assert not calls_path.exists()
        assert not (root / ".kuzushi/v3/campaigns" / plan["campaignId"] / "queue.json").exists()
        return
    jobs = wait_jobs(root, plan, {"completed"})
    assert len(jobs) == 6 and all(job["attempts"] == 1 for job in jobs.values())
    calls = [json.loads(row) for row in calls_path.read_text().splitlines()]
    assert len(calls) == 6 and len({row["bridgePid"] for row in calls}) == 6
    assert sorted(row["scope"] for row in calls) == ["app"] * 3 + ["other"] * 3
    report = read_native(root, evidence, "scope-occurrence", ["findings", "batch", plan["campaignId"], "--json"])
    for boundary in report["cases"]:
        work = boundary["occurrence"]
        assert (work["planned"], work["completed"], work["failed"], work["pending"]) == (3, 3, 0, 0)
        assert len(work["rows"]) == 1 and work["rows"][0]["seen"] == 3
        (evidence / ("open-" + boundary["id"] + ".txt")).write_text("open " + work["rows"][0]["representativeFingerprint"])
    with sqlite3.connect(root / ".kuzushi/v3/index.sqlite3") as db:
        assert db.execute("select count(*) from finding_observations").fetchone()[0] == 6
        assert db.execute("select count(*) from investigation_call_reservations").fetchone()[0] == 6
        assert db.execute("select count(*) from investigation_call_reservations where review=1 or settled_at is null").fetchone()[0] == 0
        approval = json.loads(db.execute("select approval_json from investigation_allowance_revisions order by revision desc limit 1").fetchone()[0])
        assert approval["limits"] == {"maxProviderCalls": 8, "protectedReviewCalls": 2}
        assert len(approval["workPlan"]["jobs"]) == 6
    (evidence / "finite-scopes-verified.json").write_text(json.dumps({"fixedJobs": 6, "workers": 1,
        "scopes": 2, "passesPerScope": 3, "unplanned": ["integration"], "committedCalls": 6,
        "protectedReviewCalls": 2, "freshSessions": 6, "liveRequests": 0, "sourceExecuted": False}, indent=2))


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    if sys.argv[3] == "seed":
        prepare(root, evidence, Path(sys.argv[4]).resolve())
    else:
        verify(root, evidence, sys.argv[3])
        if sys.argv[3] == "restarted":
            bodies = []
            for path in sorted(evidence.glob("*-report-*40x12.txt")):
                rows = path.read_text().splitlines()
                footer = next(index for index, row in enumerate(rows) if row.startswith("⛭"))
                bodies.extend(rows[1:footer])
            text = " ".join(" ".join(bodies).split())
            for phrase in ["6 committed / 8 calls", "2 protected review remaining", "Boundary app: 3 completed / 3 planned",
                           "Boundary other: 3 completed / 3 planned", "Unplanned boundaries: integration", "no complete repository coverage claim"]:
                assert phrase in text, "Paged narrow report did not expose " + phrase
